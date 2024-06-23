from fastapi import APIRouter, status, Depends, HTTPException
from typing import List
from sqlalchemy.orm import Session
from db.session import get_db
from schemas.blog import CreateBlog, ShowBlog
from db.repository.blog import create_new_blog, retrieve_blog, list_all_active_blogs

router = APIRouter()


@router.post("/", response_model=ShowBlog, status_code=status.HTTP_201_CREATED)
def create_blog(blog: CreateBlog, db: Session = Depends(get_db)):
    blog = create_new_blog(blog=blog, db=db, author_id=1)
    return blog


@router.get("/{id}", response_model=ShowBlog)
def get_blog(id: int, db: Session = Depends(get_db)):
    blog = retrieve_blog(id=id, db=db)
    if not blog:
        raise HTTPException(
            detail=f"Blog with id {id} does not exist",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return blog


@router.get("", response_model=List[ShowBlog])
def get_all_active_blogs(db: Session = Depends(get_db)):
    blogs = list_all_active_blogs(db=db)
    return blogs
