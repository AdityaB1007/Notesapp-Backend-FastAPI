import os
import uuid
import html 
from datetime import datetime
from fastapi.responses import RedirectResponse
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, ForeignKey, Table, Integer
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
#from passlib.context import CryptContext
from jose import JWTError, jwt
import hashlib
import secrets

SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-change-in-production-12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

#pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

DATABASE_URL = "sqlite:///./notes.db"

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False, "timeout": 30}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Many-to-Many association table for shared notes
note_shares = Table(
    "note_shares",
    Base.metadata,
    Column("note_id", String, ForeignKey("notes.id", ondelete="CASCADE")),
    Column("user_id", String, ForeignKey("users.id", ondelete="CASCADE"))
)

class UserDB(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    notes = relationship("NoteDB", back_populates="owner")
    shared_notes = relationship("NoteDB", secondary=note_shares, back_populates="shared_with")

class NoteDB(Base):
    __tablename__ = "notes"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String, nullable=False)
    content = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_deleted = Column(Boolean, default=False)
    
    #Version column added to track updates and prevent concurrent overwrite race conditions
    version = Column(Integer, default=1, nullable=False)
    
    owner_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    owner = relationship("UserDB", back_populates="notes")
    shared_with = relationship("UserDB", secondary=note_shares, back_populates="shared_notes")

Base.metadata.create_all(bind=engine)

#PYDANTIC SCHEMAS(VALIDATION)
class UserRegisterSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters")

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str

class TokenSchema(BaseModel):
    access_token: str

class NoteCreateUpdateSchema(BaseModel):
    title: str = Field(..., max_length=100, description="Title cannot be empty")
    content: str = Field(..., description="Content cannot be empty")
    
    #Required only for updates (PUT) to ensure client is editing the freshest version
    version: Optional[int] = Field(None, description="The current version of the note being updated")

    #Strip leading/trailing whitespaces and sanitize raw strings against XSS attacks
    @field_validator("title", "content")
    @classmethod
    def validate_and_sanitize(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field cannot be empty or consist solely of whitespace.")
        return html.escape(stripped) # Neutralizes malicious script tags

class NoteResponseSchema(BaseModel):
    id: str
    title: str
    content: str
    version: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ShareNoteSchema(BaseModel):
    share_with_email: EmailStr

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> UserDB:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    
    user = db.query(UserDB).filter(UserDB.email == email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

app = FastAPI(title="Multi-User Notes API", version="1.1.0")

#ENDPOINTS 

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")

@app.post("/register", status_code=status.HTTP_201_CREATED, responses={400: {"description": "Email already registered"}})
def register(user_data: UserRegisterSchema, db: Session = Depends(get_db)):
    existing_user = db.query(UserDB).filter(UserDB.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    salt = secrets.token_hex(16)
    # Hashing the password combined with the salt
    hash_obj = hashlib.sha256((user_data.password + salt).encode())
    hashed_pw = f"{salt}${hash_obj.hexdigest()}"
    
    new_user = UserDB(email=user_data.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/login", responses = {401: {"description": "Invalid email or password"}})
def login(credentials: UserLoginSchema, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == credentials.email).first()
    if not user:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
    
    # Split the stored password into salt and hash
    try:
        salt, stored_hash = user.hashed_password.split("$")
        # Hash the incoming password with the retrieved salt
        incoming_hash = hashlib.sha256((credentials.password + salt).encode()).hexdigest()
        is_valid = secrets.compare_digest(stored_hash, incoming_hash)
    except ValueError:
        is_valid = False

    if not is_valid:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid email or password"})
    
    token_data = {"sub": user.email}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token}

@app.get("/notes", response_model=List[NoteResponseSchema])
def get_notes(skip: int = Query(0, ge=0), limit: int = Query(10, ge=1, le=100), current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    owned_notes = db.query(NoteDB).filter(NoteDB.owner_id == current_user.id, NoteDB.is_deleted == False).all()
    shared_notes = db.query(NoteDB).join(NoteDB.shared_with).filter(UserDB.id == current_user.id, NoteDB.is_deleted == False).all()
    
    all_notes = list(set(owned_notes + shared_notes))
    all_notes.sort(key=lambda x: x.updated_at, reverse=True)
    return all_notes[skip : skip + limit]

@app.get("/notes/search", response_model=List[NoteResponseSchema])
def search_notes(q: str = Query(..., min_length=1), current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    search_filter = f"%{q}%"
    owned = db.query(NoteDB).filter(NoteDB.owner_id == current_user.id, NoteDB.is_deleted == False, (NoteDB.title.like(search_filter) | NoteDB.content.like(search_filter))).all()
    shared = db.query(NoteDB).join(NoteDB.shared_with).filter(UserDB.id == current_user.id, NoteDB.is_deleted == False, (NoteDB.title.like(search_filter) | NoteDB.content.like(search_filter))).all()
    return list(set(owned + shared))

@app.get("/notes/trash", response_model=List[NoteResponseSchema])
def view_trash(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(NoteDB).filter(NoteDB.owner_id == current_user.id, NoteDB.is_deleted == True).all()

@app.post("/notes/{id}/restore", responses={
        400: {"description": "Note is already active"},
        404: {"description": "Note not found in trash"}
    })
def restore_note(id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    note = db.query(NoteDB).filter(NoteDB.id == id, NoteDB.owner_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found in trash")
    if not note.is_deleted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Note is already active")
    
    note.is_deleted = False
    db.commit()
    return {"message": "Note successfully restored"}

@app.get("/notes/{id}", response_model=NoteResponseSchema, responses={
        403: {"description": "Access denied: User is neither owner nor shared recipient"},
        404: {"description": "Note not found"}
    })
def get_note_by_id(id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    note = db.query(NoteDB).filter(NoteDB.id == id, NoteDB.is_deleted == False).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    
    is_shared = db.query(NoteDB).join(NoteDB.shared_with).filter(NoteDB.id == id, UserDB.id == current_user.id).first()
    if note.owner_id != current_user.id and not is_shared:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    return note

@app.post("/notes", response_model=NoteResponseSchema, status_code=status.HTTP_201_CREATED)
def create_note(note_data: NoteCreateUpdateSchema, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    new_note = NoteDB(title=note_data.title, content=note_data.content, owner_id=current_user.id)
    db.add(new_note)
    db.commit()
    db.refresh(new_note)
    return new_note

@app.put("/notes/{id}", response_model=NoteResponseSchema, responses={
        403: {"description": "Only the owner can update this note"},
        404: {"description": "Note not found"},
        409: {"description": "Resource Conflict: Version mismatch"}
    })
def update_note(id: str, note_data: NoteCreateUpdateSchema, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    note = db.query(NoteDB).filter(NoteDB.id == id, NoteDB.is_deleted == False).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    
    if note.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Only the owner can update this note"
        )

    # Check authorization (allow shared users or owners to write, depending on your app rules)
    is_shared = db.query(NoteDB).join(NoteDB.shared_with).filter(NoteDB.id == id, UserDB.id == current_user.id).first()
    if note.owner_id != current_user.id and not is_shared:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only authorized users can update this note")
    
    # Optimistic Locking Verification
    if note_data.version is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing note version parameter.")
        
    if note.version != note_data.version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Resource Conflict: This note has been modified by another session. Please refresh your data."
        )
    
    note.title = note_data.title
    note.content = note_data.content
    note.version += 1  # Increment version string to seal against concurrent collisions
    note.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(note)
    return note

@app.delete("/notes/{id}", status_code=status.HTTP_204_NO_CONTENT, responses={
        403: {"description": "Only the owner can delete this note"},
        404: {"description": "Note not found"}
    })
def delete_note(id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    note = db.query(NoteDB).filter(NoteDB.id == id, NoteDB.is_deleted == False).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    
    if note.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the owner can delete this note")
    
    note.is_deleted = True
    db.commit()
    return

@app.delete("/notes/{id}/permanent", status_code=status.HTTP_204_NO_CONTENT, responses={
        403: {"description": "Only the owner can delete this note"},
        404: {"description": "Note not found"}
    })
def permanently_delete_note(id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    # We don't filter by is_deleted here so the user can permanently delete it whether it's in the trash or not
    note = db.query(NoteDB).filter(NoteDB.id == id).first()
    
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    
    if note.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the owner can permanently delete this note")
    
    # Actually remove the row from the database
    db.delete(note)
    db.commit()
    return

@app.post("/notes/{id}/share", responses={
        400: {"description": "Invalid sharing target (e.g., sharing with self)"},
        403: {"description": "Only the owner can share this note"},
        404: {"description": "Note or target user does not exist"}
    })
def share_note(id: str, payload: ShareNoteSchema, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    note = db.query(NoteDB).filter(NoteDB.id == id, NoteDB.is_deleted == False).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    
    if note.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the owner can share this note")
    
    if payload.share_with_email == current_user.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot share a note with yourself")
    
    target_user = db.query(UserDB).filter(UserDB.email == payload.share_with_email).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user to share with does not exist")
    
    if target_user in note.shared_with:
        return {"message": f"Note is already shared with {payload.share_with_email}"}
        
    note.shared_with.append(target_user)
    db.commit()
    return {"message": f"Note shared successfully with {payload.share_with_email}"}

@app.get("/about")
def about():
    return {
        "name": "Aditya Baranwal",
        "email": "adityabaranwal007@gmail.com",
        "my features": {
            "Trash Bin & Permanent Purge": "Implements a multi-stage deletion lifecycle (Soft Delete for recovery safety, Hard Delete for total data destruction), preventing accidental loss while ensuring absolute data privacy control.",
            "Optimistic Concurrency Control": "Prevents the 'last-write-wins' race condition on collaborative shared notes by enforcing strict item version tracking, isolating overlapping user edits with clean 409 Conflict protections.",
            "XSS Mitigation & Input Sanitization": "Guarantees strict whitespace-trimming validation and transforms raw text injections to neutralize malicious HTML/JS payloads before storing data into SQLite."
           }
    }
