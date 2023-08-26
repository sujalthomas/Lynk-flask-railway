import openai
from docx import Document
import PyPDF2

# Utils ###############
# Define utils #######

def is_api_key_valid(api_key):
    openai.api_key = api_key
    try:
        response = openai.Completion.create(
            engine="davinci", prompt="This is a test.", max_tokens=5
        )
    except:
        return False
    else:
        return True

def convert_to_txt(file, file_type):
    if file_type == "docx":
        doc = Document(file)
        return "\n".join([p.text for p in doc.paragraphs])
    elif file_type == "pdf":
        reader = PyPDF2.PdfReader(file)
        return "\n".join(
            [reader.pages[i].extract_text() for i in range(len(reader.pages))]
        )
    else:
        raise ValueError("Unsupported file type")
