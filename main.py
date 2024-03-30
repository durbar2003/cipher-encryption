import string
import random
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad

class SubstitutionCipher:
    def __init__(self, key=None):
        if key is None:
            key = self.generate_default_key()
        self.key = key

    def generate_default_key(self):
        alphabet = list(string.ascii_lowercase + string.ascii_uppercase)
        random.shuffle(alphabet)
        while not alphabet:  # Loop until alphabet has at least one character
            missing_char = random.choice(string.ascii_lowercase + string.ascii_uppercase)
            alphabet.append(missing_char)
        return ''.join(alphabet)

    def shift_encrypt(self, plaintext, shift):
        encrypted_text = ''
        for char in plaintext:
            if char.isalpha():
                if char.isupper():
                    encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encrypted_char = char  # Preserve non-alphabetic characters
            encrypted_text += encrypted_char
        return encrypted_text

    def shift_decrypt(self, ciphertext, shift):
        decrypted_text = ''
        for char in ciphertext:
            if char.isalpha():
                if char.isupper():
                    decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                decrypted_char = char  # Preserve non-alphabetic characters
            decrypted_text += decrypted_char
        return decrypted_text

    def permutation_encrypt(self, plaintext):
        encrypted_text = ''
        for char in plaintext:
            if char.isalpha():
                idx = (ord(char.lower()) - ord('a'))
                encrypted_char = self.key[idx].upper() if char.isupper() else self.key[idx]
            else:
                encrypted_char = char  # Preserve non-alphabetic characters
            encrypted_text += encrypted_char
        return encrypted_text

    def permutation_decrypt(self, ciphertext):
        decrypted_text = ''
        for char in ciphertext:
            if char.isalpha():
                idx = self.key.find(char.lower())
                decrypted_char = chr(idx + ord('a')).upper() if char.isupper() else chr(idx + ord('a'))
            else:
                decrypted_char = char  # Preserve non-alphabetic characters
            decrypted_text += decrypted_char
        return decrypted_text

    def encrypt(self, plaintext, method='shift', shift=None):
        if method == 'shift':
            if shift is None:
                shift = random.randint(1, 25)
            return self.shift_encrypt(plaintext, shift)
        elif method == 'permutation':
            return self.permutation_encrypt(plaintext)
        else:
            raise ValueError("Invalid encryption method")

    def decrypt(self, ciphertext, method='shift', shift=None):
        if method == 'shift':
            if shift is None:
                raise ValueError("Shift value must be provided for decryption")
            return self.shift_decrypt(ciphertext, shift)
        elif method == 'permutation':
            return self.permutation_decrypt(ciphertext)
        else:
            raise ValueError("Invalid decryption method")

class TranspositionCipher:
    def __init__(self, key=None):
        if key is None:
            key = self.generate_default_key()
        self.key = key

    def generate_default_key(self):
        return 3

    def single_transposition_encrypt(self, plaintext):
        encrypted_text = ''
        for i in range(0, len(plaintext), self.key):
            encrypted_text += plaintext[i:i+self.key][::-1]
        return encrypted_text

    def double_transposition_encrypt(self, plaintext):
        temp_cipher = self.single_transposition_encrypt(plaintext)
        return self.single_transposition_encrypt(temp_cipher)

    def encrypt(self, plaintext, method='single'):
        if method == 'single':
            return self.single_transposition_encrypt(plaintext)
        elif method == 'double':
            return self.double_transposition_encrypt(plaintext)
        else:
            raise ValueError("Invalid encryption method")

    def single_transposition_decrypt(self, ciphertext):
        decrypted_text = ''
        for i in range(0, len(ciphertext), self.key):
            decrypted_text += ciphertext[i:i+self.key][::-1]
        return decrypted_text

    def double_transposition_decrypt(self, ciphertext):
        temp_plain = self.single_transposition_decrypt(ciphertext)
        return self.single_transposition_decrypt(temp_plain)

    def decrypt(self, ciphertext, method='single'):
        if method == 'single':
            return self.single_transposition_decrypt(ciphertext)
        elif method == 'double':
            return self.double_transposition_decrypt(ciphertext)
        else:
            raise ValueError("Invalid decryption method")


import string
import random

class VigenereCipher:
    def __init__(self, key=None):
        self.default_key = 'me'
        if key is None:
            self.key = self.default_key
        else:
            self.key = key.upper()

    def encrypt(self, plaintext):
        key_to_use = self.key if self.key != self.default_key else self.default_key
        key_len = len(key_to_use)
        encrypted_text = ''
        for i, char in enumerate(plaintext):
            if char.isalpha():
                shift = ord(key_to_use[i % key_len]) - ord('A')
                if char.isupper():
                    new_ord = (ord(char) - ord('A') + shift) % 26 + ord('A')
                else:
                    new_ord = (ord(char) - ord('a') + shift) % 26 + ord('a')
                encrypted_text += chr(new_ord)
            else:
                encrypted_text += char  # Preserve non-alphabetic characters
        return encrypted_text

    def decrypt(self, ciphertext):
        key_to_use = self.key if self.key != self.default_key else self.default_key
        key_len = len(key_to_use)
        decrypted_text = ''
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                shift = ord(key_to_use[i % key_len]) - ord('A')
                if char.isupper():
                    new_ord = (ord(char) - ord('A') - shift) % 26 + ord('A')
                else:
                    new_ord = (ord(char) - ord('a') - shift) % 26 + ord('a')
                decrypted_text += chr(new_ord)
            else:
                decrypted_text += char  # Preserve non-alphabetic characters
        return decrypted_text






import os

class AESCipher:
    def __init__(self, key=None):
        if not key:
            key = self.generate_random_key()
        self.key = key

    def generate_random_key(self):
        return os.urandom(16)  

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_plaintext = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted_text = cipher.decrypt(ciphertext)
        unpadded_text = unpad(decrypted_text, AES.block_size)
        return unpadded_text.decode()

class DESCipher:
    def __init__(self, key=None):
        if not key:
            key = self.generate_random_key()
        self.key = key

    def generate_random_key(self):
        return os.urandom(8)

    def encrypt(self, plaintext):
        cipher = DES.new(self.key, DES.MODE_ECB)
        padded_plaintext = pad(plaintext.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        cipher = DES.new(self.key, DES.MODE_ECB)
        decrypted_text = cipher.decrypt(ciphertext)
        unpadded_text = unpad(decrypted_text, DES.block_size)
        return unpadded_text.decode()

class TripleDESCipher:
    def __init__(self, key=None):
        if not key:
            key = self.generate_random_key()
        self.key = key

    def generate_random_key(self):
        return os.urandom(16)

    def encrypt(self, plaintext):
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        padded_plaintext = pad(plaintext.encode(), DES3.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        decrypted_text = cipher.decrypt(ciphertext)
        unpadded_text = unpad(decrypted_text, DES3.block_size)
        return unpadded_text.decode()

class AESCFBCipher:
    def __init__(self, key=None, iv=None):
        if not key:
            key = self.generate_random_key()
        self.key = key
        self.iv = iv if iv else os.urandom(16)

    def generate_random_key(self):
        return os.urandom(16)  

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv)
        ciphertext = cipher.encrypt(plaintext.encode())
        return ciphertext

    def decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv)
        decrypted_text = cipher.decrypt(ciphertext)
        return decrypted_text.decode()

class AESOFBCipher:
    def __init__(self, key=None, iv=None):
        if not key:
            key = self.generate_random_key()
        self.key = key
        self.iv = iv if iv else os.urandom(16)

    def generate_random_key(self):
        return os.urandom(16)  

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_OFB, iv=self.iv)
        ciphertext = cipher.encrypt(plaintext.encode())
        return ciphertext

    def decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_OFB, iv=self.iv)
        decrypted_text = cipher.decrypt(ciphertext)
        return decrypted_text.decode()


def main():
    print("Choose an encryption technique:")
    print("1. Substitution cipher")
    print("2. Transposition cipher")
    print("3. Vigenere cipher")
    print("4. AES encryption")
    print("5. DES encryption")
    print("6. 3DES encryption")
    print("7. AES CFB encryption")
    print("8. AES OFB encryption")

    choice = input("Enter your choice: ")

    if choice == "1":
        plaintext = input("Enter plaintext: ")
        method = input("Choose encryption method (shift/permutation): ").lower()
        custom_key = input("Enter a custom key (press Enter to use default key): ")
        if custom_key:
            key = custom_key
        else:
            key = None
        if method == 'shift':
            shift = int(input("Enter shift value (1-25): "))
            cipher = SubstitutionCipher()
            ciphertext = cipher.encrypt(plaintext, method='shift', shift=shift)
            print("Encrypted message:", ciphertext)
            
            use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
            if use_same_key == 'yes':
                decrypted_text = cipher.decrypt(ciphertext, method='shift', shift=shift)
            elif use_same_key == 'no':
                shift = int(input("Enter the shift value used for encryption: "))
                decrypted_text = cipher.decrypt(ciphertext, method='shift', shift=shift)
            else:
                print("Invalid choice for using the same key.")
                return
        elif method == 'permutation':
            cipher = SubstitutionCipher(key)
            ciphertext = cipher.encrypt(plaintext, method='permutation')
            print("Encrypted message:", ciphertext)
            
            use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
            if use_same_key == 'yes':
                decrypted_text = cipher.decrypt(ciphertext, method='permutation')
            elif use_same_key == 'no':
                custom_key = input("Enter the custom key used for encryption: ")
                cipher = SubstitutionCipher(custom_key)
                decrypted_text = cipher.decrypt(ciphertext, method='permutation')
            else:
                print("Invalid choice for using the same key.")
                return
        else:
            print("Invalid encryption method")
            return
        print("Decrypted message:", decrypted_text)
        
    elif choice == "2":
        plaintext = input("Enter plaintext: ")
        method = input("Choose encryption method (single/double): ").lower()
        custom_key = input("Enter a custom key (press Enter to use default key): ")
        if custom_key:
            key = int(custom_key)
        else:
            key = None
        cipher = TranspositionCipher()
        if method == 'single':
            ciphertext = cipher.encrypt(plaintext, method='single', key=key)
            print("Encrypted message:", ciphertext)
            
            use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
            if use_same_key == 'yes':
                decrypted_text = cipher.decrypt(ciphertext, method='single', key=key)
            elif use_same_key == 'no':
                key = int(input("Enter the key used for encryption: "))
                decrypted_text = cipher.decrypt(ciphertext, method='single', key=key)
            else:
                print("Invalid choice for using the same key.")
                return
        elif method == 'double':
            ciphertext = cipher.encrypt(plaintext, method='double', key=key)
            print("Encrypted message:", ciphertext)
            
            use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
            if use_same_key == 'yes':
                decrypted_text = cipher.decrypt(ciphertext, method='double', key=key)
            elif use_same_key == 'no':
                key = int(input("Enter the key used for encryption: "))
                decrypted_text = cipher.decrypt(ciphertext, method='double', key=key)
            else:
                print("Invalid choice for using the same key.")
                return
        else:
            print("Invalid encryption method")
            return
        print("Decrypted message:", decrypted_text)

    elif choice == "3":
        plaintext = input("Enter plaintext: ")
        key = input("Enter Vigenere cipher key (or press Enter to use default): ")
        cipher = VigenereCipher()
        ciphertext = cipher.encrypt(plaintext)
        print("Encrypted message:", ciphertext)
        
        use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
        if use_same_key == 'yes':
            decrypted_text = cipher.decrypt(ciphertext)
        elif use_same_key == 'no':
            key = input("Enter the key used for encryption: ")
            cipher = VigenereCipher(key)
            decrypted_text = cipher.decrypt(ciphertext)
        else:
            print("Invalid choice for using the same key.")
            return
        print("Decrypted message:", decrypted_text)

    elif choice == "4":
        plaintext = input("Enter plaintext: ")
        key = input("Enter AES encryption key (or press Enter to use default): ")
        cipher = AESCipher(key.encode())
        ciphertext = cipher.encrypt(plaintext)
        print("Encrypted message:", ciphertext)
        
        use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
        if use_same_key == 'yes':
            decrypted_text = cipher.decrypt(ciphertext)
        elif use_same_key == 'no':
            key = input("Enter the key used for encryption: ")
            cipher = AESCipher(key.encode())
            decrypted_text = cipher.decrypt(ciphertext)
        else:
            print("Invalid choice for using the same key.")
            return
        print("Decrypted message:", decrypted_text)

    elif choice == "5":
        plaintext = input("Enter plaintext: ")
        key = input("Enter DES encryption key (or press Enter to use default): ")
        cipher = DESCipher(key.encode())
        ciphertext = cipher.encrypt(plaintext)
        print("Encrypted message:", ciphertext)
        
        use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
        if use_same_key == 'yes':
            decrypted_text = cipher.decrypt(ciphertext)
        elif use_same_key == 'no':
            key = input("Enter the key used for encryption: ")
            cipher = DESCipher(key.encode())
            decrypted_text = cipher.decrypt(ciphertext)
        else:
            print("Invalid choice for using the same key.")
            return
        print("Decrypted message:", decrypted_text)

    elif choice == "6":
        plaintext = input("Enter plaintext: ")
        key = input("Enter 3DES encryption key (or press Enter to use default): ")
        cipher = TripleDESCipher(key.encode())
        ciphertext = cipher.encrypt(plaintext)
        print("Encrypted message:", ciphertext)
        
        use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
        if use_same_key == 'yes':
            decrypted_text = cipher.decrypt(ciphertext)
        elif use_same_key == 'no':
            key = input("Enter the key used for encryption: ")
            cipher = TripleDESCipher(key.encode())
            decrypted_text = cipher.decrypt(ciphertext)
        else:
            print("Invalid choice for using the same key.")
            return
        print("Decrypted message:", decrypted_text)

    elif choice == "7":
        plaintext = input("Enter plaintext: ")
        key = input("Enter AES CFB encryption key (or press Enter to use default): ")
        cipher = AESCFBCipher(key.encode())
        ciphertext = cipher.encrypt(plaintext)
        print("Encrypted message:", ciphertext)
        
        use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
        if use_same_key == 'yes':
            decrypted_text = cipher.decrypt(ciphertext)
        elif use_same_key == 'no':
            key = input("Enter the key used for encryption: ")
            cipher = AESCFBCipher(key.encode())
            decrypted_text = cipher.decrypt(ciphertext)
        else:
            print("Invalid choice for using the same key.")
            return
        print("Decrypted message:", decrypted_text)

    elif choice == "8":
        plaintext = input("Enter plaintext: ")
        key = input("Enter AES OFB encryption key (or press Enter to use default): ")
        cipher = AESOFBCipher(key.encode())
        ciphertext = cipher.encrypt(plaintext)
        print("Encrypted message:", ciphertext)
        
        use_same_key = input("Do you want to use the same key for decryption? (yes/no): ").lower()
        if use_same_key == 'yes':
            decrypted_text = cipher.decrypt(ciphertext)
        elif use_same_key == 'no':
            key = input("Enter the key used for encryption: ")
            cipher = AESOFBCipher(key.encode())
            decrypted_text = cipher.decrypt(ciphertext)
        else:
            print("Invalid choice for using the same key.")
            return
        print("Decrypted message:", decrypted_text)

    else:
        print("Invalid choice")
j=1
while j:
    if __name__ == "__main__":
        main()
