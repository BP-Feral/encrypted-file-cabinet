# Encrypted File Cabinet

An application that securely encrypts and decrypts files using a password. The application allows users to add, view, and remove encrypted files from a vault. The files are encrypted with a password-based key, and decrypted using the same password.

## Features

- **Password-based encryption**: Files are encrypted using a password that is hashed and used to generate a Fernet key.
- **File Vault**: Files are stored securely in an encrypted vault.
- **Unvaulting**: Files can be decrypted and saved to a separate folder for access.
- **Password Re-entry**: Users can re-enter the password to decrypt files.
- **File Management**: Users can refresh the vault, add new files, and delete files from the vault.

## Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/BP-Feral/encrypted-file-cabinet.git
    ```

2. Navigate to the project directory:

    ```bash
    cd encrypted-file-cabinet
    ```

3. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the application:

    ```bash
    python VaultApp.py
    ```

2. When prompted, enter a password. This password will be used to encrypt and decrypt files.
3. Add files to the vault by selecting "Add File" and choosing the files you want to encrypt.
4. View encrypted files in the vault. You can decrypt them or remove them from the vault as needed.
5. If you need to open the "unvaulted" folder, use the "Open Unvaulted Folder" button.

Note! each file can be encrypted with its own password so in order to decrypt files you need the original passwrd!

## Encryption and Decryption Process

The encryption process is based on a password that is hashed using the SHA-256 algorithm and then used to generate a Fernet encryption key. This key is used to encrypt and decrypt files. Files are read and written in binary format, with encryption scrambling the binary data, ensuring that unauthorized users cannot access the original file contents.

For more details on how encryption and decryption works, refer to the **Encryption and Decryption Process** section in the documentation.

## Technologies Used

- **Python 3.x**
- **CustomTkinter**: For the graphical user interface (GUI).
- **Cryptography Library**: For encryption and decryption of files using the Fernet algorithm.
- **SHA-256**: For hashing the password to generate the encryption key.

## Directory Structure

- `VaultApp.py`: Main application file.
- `vault/`: Directory to store encrypted files.
- `unvaulted/`: Directory to store decrypted files.
- `requirements.txt`: File with project dependencies.

## Contributing

If you have suggestions or improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Identified Issues

If the app name gets renamed to just "vault" or "Vault", trying to open the file location through the Application, it will mistake the "vault" folder with the "vault.exe" and start a new instance instead.