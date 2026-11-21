from pydantic import BaseModel, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("full_name")
    @classmethod
    def clean_name(cls, value):
        return " ".join(value.split())


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class RegisterKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    public_key_pem: str = Field(min_length=40, max_length=10000)
    challenge_id: str = Field(min_length=36, max_length=36)
    proof_signature: str = Field(min_length=40, max_length=1000)  # ECDSA DER ~96 chars, RSA 344-684


class AdminUserUpdate(BaseModel):
    role: str | None = Field(default=None, pattern=r"^(user|admin)$")
    status: str | None = Field(default=None, pattern=r"^(active|suspended)$")


class DocumentSendForm(BaseModel):
    pass


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=12, max_length=128)
