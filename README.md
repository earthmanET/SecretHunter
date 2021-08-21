# SecretHunter
Secrethunter is a password information extraction tool for Windows platform. Currently, the supported functions include:
- extract the password data stored by browsers (Chrome, Firefox, Edge and IE)
- extract the password data stored by the Security Account Manager (SAM)
- extract the password data in LSASS process
- extract the GitHub password data and RDP password data stored in Windows credential manager

More functions are still being further improved. 

## Installation
```
git clone 
```
```
pip3 install -r requirements.txt
```

## Usage
Start SecretHunter and extract password data.
```
python3 SecretHunter.py
```
Specifies the path of the output file.
```
python3 SecretHunter.py -o /output/file/path
```
