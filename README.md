# OCR-Paddle Anonymizer

A powerful tool for automatic detection and anonymization of sensitive information in documents using OCR technology and AI.

## Overview

The OCR-Paddle Anonymizer automatically detects and redacts sensitive information in scanned documents, IDs, passports, and other image media. By combining PaddleOCR for text recognition, spaCy for entity recognition, and optional LLM integration (via Ollama), the tool provides a robust solution for document anonymization.

## Features

- **Automatic Text Recognition** with PaddleOCR
- **Intelligent Sensitive Data Detection** using spaCy and custom rules
- **Specialized Passport and ID Recognition** with support for MRZ lines (Machine Readable Zone)
- **LLM-based Verification** (optional) for reducing false positives
- **Configurable Sensitivity Rules** via a simple text file
- **Support for Various Document Types** such as research papers, medical documents, passports, and IDs

## Installation

### Prerequisites

- Python 3.8 or higher
- PaddleOCR
- spaCy with German and English language models
- Ollama (optional, for LLM integration)

### Installing Dependencies

```bash
# Install required Python packages
pip install -r requirements.txt

# Download spaCy language models
python -m spacy download en_core_web_sm
python -m spacy download en_core_web_md  # Optional, for improved recognition
python -m spacy download de_core_news_sm  # For German documents
```

For LLM integration:

1. [Install Ollama](https://github.com/ollama/ollama)
2. Download a supported model, e.g.:
   ```
   ollama pull qwen2.5vl:3b
   ```

## Usage

### Basic Usage

```bash
python anonymizer.py --input path/to/document.png --output anonymized_document.png
```

### Options

```plaintext
--input, -i       Path to the input file (image)
--output, -o      Path to the output file (anonymized image)
--model, -m       Ollama model for LLM verification (default: qwen2.5vl:3b)
--rules, -r       Path to the rules file (default: sensitive_data_rules.txt)
--nollm           Disables LLM verification
--debug, -d       Enables debug mode with detailed output
--passport, -p    Indicates that the document is a passport/ID (improves detection)
--ollama-url      URL of the Ollama server (default: http://localhost:11434)
```

### Examples

**Anonymizing a simple document:**

```bash
python anonymizer.py -i document.png -o anonymized.png
```

**Anonymizing a passport with debug output:**

```bash
python anonymizer.py -i passport.png -o anonymized_passport.png --passport --debug
```

**Usage without LLM verification:**

```bash
python anonymizer.py -i document.png -o anonymized.png --nollm
```

**Usage with custom rules:**

```bash
python anonymizer.py -i document.png -o anonymized.png --rules my_rules.txt
```

## Configuring Sensitivity Rules

The file `sensitive_data_rules.txt` defines which types of information are considered sensitive and should be anonymized. The file has the following format:

```plaintext
# Comment
entity:ENTITY_TYPE    # spaCy entity types (e.g., PERSON, DATE)
keyword:keyword       # Keywords that indicate sensitive data
regex:pattern         # Regular expressions for specific patterns
```

### Example of Sensitivity Rules

```plaintext
# Entity types
entity:PERSON
entity:DATE

# Keywords
keyword:birth
keyword:name
keyword:address

# Regex patterns
regex:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}  # Date format
regex:[A-Z0-9]{6,10}                    # Typical ID number
```

## Special Passport and ID Recognition

The Anonymizer includes special functions for the detection and anonymization of passports and IDs:

- Detection of MRZ lines (Machine Readable Zone)
- Identification of passport numbers and ID data
- Extraction of structured data
- Intelligent redaction of sensitive areas

Enable the passport mode with the `--passport` option for optimal results.

## Troubleshooting

### Issues with the Ollama API

If you receive errors like `Error with Ollama API request: Status 500`:

1. Make sure the Ollama server is running
2. Check if the specified model is loaded
3. For persistent problems, use the `--nollm` option to disable LLM verification

### Improving OCR Quality

For better results:

- Use images with good resolution and clear contrast
- Make sure the document is well lit
- Experiment with different sensitivity rules

## Technical Details

### Algorithm

1. **Text Recognition**: Extracts text and its position in the document using PaddleOCR
2. **Entity Recognition**: Identifies named entities (names, places, dates) with spaCy
3. **Rule-based Detection**: Applies custom rules (keywords, regex)
4. **LLM Verification**: (Optional) Verifies detected information with an LLM
5. **Redaction**: Blacks out areas identified as sensitive in the original image

### Modules

- `anonymize_document`: Main function for document processing
- `detect_passport_structure`: Specialized in the detection of passports/IDs
- `parse_passport_mrz`: Extracts information from MRZ lines
- `extract_sensitive_values`: Finds sensitive values next to keywords
- `get_sensitive_regions`: Identifies areas to be redacted

## Author

- [Hamed Haidari]

## Acknowledgments

- [PaddleOCR](https://github.com/PaddlePaddle/PaddleOCR) for the OCR technology
- [spaCy](https://spacy.io/) for entity recognition
- [Ollama](https://github.com/ollama/ollama) for local LLM integration
