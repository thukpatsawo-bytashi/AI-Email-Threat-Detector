from fastapi import FastAPI, UploadFile, File, HTTPException
from email_parser import parse_email

app = FastAPI(
    title="AI Email Threat Detector",
    description="Email upload and parsing API",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "message": "AI Email Threat Detector API is running"
    }


@app.post("/upload")
async def upload_email(file: UploadFile = File(...)):

    # Check file extension
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported."
        )

    # Read uploaded file
    file_data = await file.read()

    # Check if file is empty
    if not file_data:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty."
        )

    # Parse the email
    try:
        parsed_email = parse_email(file_data)

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to parse email: {str(e)}"
        )

    # Return parsed information
    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "email": parsed_email
    }