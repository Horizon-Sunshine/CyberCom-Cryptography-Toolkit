# CyberCom Cryptography Toolkit

A modular, educational cybersecurity toolkit featuring multiple encryption, decryption, and attack simulation utilities, powered by a graphical user interface (GUI).  
Developed by Ben Cohen, Ofek Shemesh, and Ben Zion.

---

### Overview

This application provides a unified GUI for performing several classic cybersecurity tasks and cryptographic algorithms.  
It is designed for laboratory exercises, demonstrations, and learning scenarios in cyber and information security education.

---

### Features

- **Fake Data Generation**  
  Create realistic, localized fake identities for testing and demos using the Faker library.  
  Supported locales: `en_US`, `he_IL`, `ja_JP`, `it_IT`.

- **Keyword Search in Source Code**  
  Scan web page source code for specific keywords using HTTP requests.

- **Encryption Utilities**  
  - Fernet symmetric encryption/decryption (random key)  
  - SHA256 hashing

- **Caesar Cipher**  
  - Table-based brute-force deciphering

- **Vigenère Cipher**  
  - Generate brute-force decryption tables with configurable key and jump values

- **Subset Sum (MSSP) Decryption**  
  - Attempt decryption on Multiple Subset Sum Problem (MSSP) formatted ciphertext

- **DDoS Simulation**  
  - Multi-threaded socket-based attack utility for demonstration/testing (educational use only)

Each feature is accessible through dedicated tabs inside the intuitive `tkinter` GUI.

---

### Installation

#### Requirements

Install these Python packages before running the project:
pip install tkinter requests faker cryptography

#### How to Run

Simply execute:
python Final_Project_CyberCom.py

The main window will appear, providing tabbed access to all modules.

---

### Usage

- **Select the desired tab (Faker, Requests, Encryption, Caesar, Vigenère, MSSP, DDoS)**
- Enter the relevant information in the form fields
- Click the action button to see results in the output box
- For DDoS simulation, ensure you have a test environment—this is for educational demonstration only.

---

### Architecture

- Object-oriented and modular design for clear separation of cryptographic and utility functions  
- All main logic and GUI wiring are in a single file for simplicity  
- Uses multithreading for DDoS simulation and responsive UI updates

---

### License

This project is intended for academic and educational use.  
Use responsibly and do not deploy attack modules on unauthorized networks.

---

### Acknowledgements

- Python standard libraries  
- Open-source packages: `tkinter`, `requests`, `faker`, `cryptography`

---
