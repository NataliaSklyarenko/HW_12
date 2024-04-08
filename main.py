@app.post("/register/", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password, full_name=user.full_name)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user
@app.post("/login/", response_model=dict)
def login_user(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/contacts/", response_model=Contact, status_code=status.HTTP_201_CREATED)
def create_contact(contact: ContactCreate, current_user: str = Depends(decode_token), db: Session = Depends(get_db)):
    new_contact = Contact(**contact.dict(), owner_email=current_user)
    db.add(new_contact)
    db.commit()
    db.refresh(new_contact)
    return new_contact

@app.put("/contacts/{contact_id}", response_model=Contact)
def update_contact(contact_id: int, contact: ContactUpdate, current_user: str = Depends(decode_token), db: Session = Depends(get_db)):
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_email == current_user).first()
    if db_contact:
        for key, value in contact.dict().items():
            setattr(db_contact, key, value)
        db.commit()
        db.refresh(db_contact)
        return db_contact
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")

@app.delete("/contacts/{contact_id}", response_model=Contact)
def delete_contact(contact_id: int, current_user: str = Depends(decode_token), db: Session = Depends(get_db)):
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_email == current_user).first()
    if db_contact:
        db.delete(db_contact)
        db.commit()
        return db_contact
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    email = Column(String, index=True)
    phone_number = Column(String, index=True)
    birth_date = Column(Date)
    extra_data = Column(String, nullable=True)
    owner_email = Column(String, index=True)
