
## Mnemonic Phrase Creator

This Python script creates a mnemonic expression and allows the user to continuously generate expressions and save them in a file called `seed.txt`.
### Requirements

- Python 3.x
- `mnemonic` library

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/pizdelor/Random-Mnemonic-Phrase-Generator.git
   ```
   ```
   cd Random-Mnemonic-Phrase-Generator
   ```

2. Install the required Python libraries:

   ```bash
   pip install -r requirements.txt
   ```

### Usage

Run the script using Python:

```bash
python generator.py
```

### Options

- After every 100 generated mnemonic phrases, the script prompts the user with a message asking if they want to continue generating more phrases. Respond with 'y' to continue or any other key to terminate the loop.

### Note

The generated mnemonic phrases are appended to the `seed.txt` file in the project directory.

### Contribution

Feel free to contribute by forking the repository and submitting pull requests.

### License

This project is licensed under the [MIT License](LICENSE).

---
