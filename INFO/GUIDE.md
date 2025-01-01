# How do I use each of these tools?

## Vuln.Scan

How to Use Vuln.Scan?

Ensure you have all the required dependencies installed. You can install the required Python libraries using:
pip install -r requirements.txt

Run the Script:
Execute the Vuln.Scan.py script. For example:
python Vuln.Scan.py

Check Results:
The scan results will be saved to a file named scan_results.json in the same directory.
Open this file to view the detected vulnerabilities.
That's it! The script will handle scanning the specified targets, checking for vulnerabilities, and saving the results.

## Web.Monitor

How to use Web.Monitor:

Ensure you have all the required dependencies installed.
You can install the required Python libraries using:
pip install -r requirements.txt

Edit Configuration:
Edit the `email_config.ini` file to specify your email configurations.
Use the `encrypt_password.py` script to securely enter your email password.
Also, edit the `web_url_config.ini` file to specify the website URL to be monitored. Ensure the files are correctly configured before running the script.

Run the Script:
Execute the Web.Monitor.py script. For example:
python Web.Monitor.py

Check Results:
If a vulnerability is detected, an alert will be sent via email. (According to what was input into the `email_config.ini` file.)

## Vuln.Monitor

How to use Vuln.Monitor:

Ensure you have all the required dependencies installed.
You can install the required Python libraries using:
pip install -r requirements.txt

Edit Configuration:
Edit the `email_config.ini` file to specify your email configurations.

Run the Script:
Execute the Vuln.Monitor.py script with the necessary parameters. For example:
python Vuln.Monitor.py

Check Results:
If a vulnerability is detected, an alert will be sent via email. (According to what was input into the `email_config.ini` file.)