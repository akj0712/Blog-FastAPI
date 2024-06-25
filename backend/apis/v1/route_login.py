from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi import Depends, APIRouter, status, HTTPException
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from db.session import get_db
from core.hashing import Hasher
from db.repository.login import get_user_by_email
from core.security import create_access_token
from core.config import settings

router = APIRouter()


def autheticate_user(email: str, password: str, db: Session):
    user = get_user_by_email(email=email, db=db)

    if not user:
        return False
    if not Hasher.verify_password(password, user.password):
        return False
    return user


@router.post("/token")
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = autheticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            detail="Incorrect Email or Password",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/token")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentails_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not verify credentials, Please login again",
    )
    print(token)
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        email: str = payload.get("sub")
        if email is None:
            print("-> Email")
            raise credentails_exception

    except JWTError:
        print("-> JWT")
        raise credentails_exception

    user = get_user_by_email(email=email, db=db)
    if user is None:
        print("-> User")
        raise credentails_exception

    return user
