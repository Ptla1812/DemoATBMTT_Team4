from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)

    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)

def sign_message(message, private_key_path):
    try:
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature
    except FileNotFoundError:
        print(f"Không tìm thấy file khóa bí mật: {private_key_path}")
        return None
    except Exception as e:
        print(f"Lỗi khi tạo chữ ký số: {e}")
        return None

def verify_signature(message, signature, public_key_path):
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Tạo cặp khóa
generate_key_pair()

# Nhập thông điệp và khóa bí mật từ người dùng
message = input("Nhập thông điệp giao dịch: ")
private_key_path = input("Nhập đường dẫn đến khóa bí mật: ")

# Tạo chữ ký số
signature = sign_message(message, private_key_path)

# Kiểm tra nếu chữ ký không được tạo thành công
if signature is None:
    print("Giao dịch không hợp lệ.")
else:
    print(f"Chữ ký số: {signature}")

# Người dùng gửi thông điệp và chữ ký lên hệ thống
# Hệ thống kiểm tra tính hợp lệ của chữ ký bằng khóa công khai
public_key_path = 'public_key.pem'
if verify_signature(message, signature, public_key_path):
    print("Giao dịch hợp lệ.")
else:
    print("Giao dịch không hợp lệ.")

