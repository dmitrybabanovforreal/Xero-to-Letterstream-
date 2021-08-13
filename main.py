#! /usr/bin/python3
import traceback, logging, requests, datetime, os, PyPDF2, base64, hashlib, json, io
from base64 import b64encode
from flask import Flask, request, Response, redirect
import config


app = Flask(__name__)
if 'logs' not in os.listdir(os.getcwd()):
    os.mkdir('logs')


application_path = os.path.dirname(os.path.abspath(__file__))
sfConfig = json.load(open(os.path.join(application_path, 'sf_config.json')))


@app.route(config.authSlug)
def authorization():
    # Update the log parameters with the new filename
    reportName = os.path.join('logs', 'log ' + datetime.datetime.now().strftime('%Y-%m') + '.txt')
    logging.basicConfig(filename=reportName, level=logging.INFO, format=' %(asctime)s -  %(levelname)s -  %(message)s')

    try:
        token = open('token').read()
    except:
        token, refreshToken = '', ''

    # if the is no token, launch the process of the app authorization
    if token == '':
        # check if user returned from the authorization page with the code
        # https://developer.xero.com/documentation/oauth2/auth-flow#redirect
        authCode = request.args.get('code')
        if authCode:
            # send the code to get the token
            # https://developer.xero.com/documentation/oauth2/auth-flow#code
            s = config.id + ":" + config.secret
            headers = {'Authorization': 'Basic ' + str(b64encode(s.encode("utf-8")), "utf-8")}
            data = {
                'grant_type': 'authorization_code',
                'code': authCode,
                'redirect_uri': config.appAddress + config.authSlug
            }
            response = requests.post('https://identity.xero.com/connect/token', headers=headers, data=data)
            token = response.json()['access_token']
            refreshToken = response.json()['refresh_token']

            file = open('token', 'w')
            file.write(token)
            file.close()

            file = open('refreshToken', 'w')
            file.write(refreshToken)
            file.close()

            # get the tennant ID
            # https://developer.xero.com/documentation/oauth2/auth-flow#connections
            headers = {'Authorization': 'Bearer ' + token}
            response = requests.get('https://api.xero.com/connections', headers=headers)
            tenantId = response.json()[0]['tenantId']
            file = open('tenantId', 'w')
            file.write(tenantId)
            file.close()

            logging.info('The app got authorized')

            return f'The app is authorized. You can now call {config.appAddress}{config.invoicesSlug} to trigger the ' \
                   f'invoices processing.\n\nYou can pass startdate and enddate parameters in YYYY-MM-DD format to ' \
                   f'specify the invoices dates.\n\nBy default it processes all invoices generated yesterday'

        else:
            # send the authorization request to get the code
            # https://developer.xero.com/documentation/oauth2/auth-flow#authorize
            redirectUrl = f'https://login.xero.com/identity/connect/authorize?response_type=code&client_id={config.id}&redirect_uri={config.appAddress}{config.authSlug}&scope={config.scope}'
            logging.info('The app authorization url is called, no token found. Redirecting to ' + redirectUrl)
            return redirect(redirectUrl)
    else:
        logging.info('The app authorization url is called but the app is already authorized')
        return 'The app is already authorized'


@app.route(config.invoicesSlug)
def process_invoices():
    # Update the log parameters with the new filename
    reportName = os.path.join('logs', 'log ' + datetime.datetime.now().strftime('%Y-%m') + '.txt')
    logging.basicConfig(filename=reportName, level=logging.INFO, format=' %(asctime)s -  %(levelname)s -  %(message)s')

    try:
        # check that all the credentials are available
        try:
            token = open('token').read()
            refreshToken = open('refreshToken').read()
            tenantId = open('tenantId').read()
        except:
            logging.info('The invoices processing url is called but the app is not authorized')
            return f'Apparently, the app is not authorized yet. Open {config.appAddress}{config.authSlug} to start the ' \
                   f'authorization process'

        # since Xero token only lasts for 30 minutes and we plan to use their API daily,
        # we need almost always start with refreshing the token
        # https://developer.xero.com/documentation/oauth2/auth-flow#refresh
        s = config.id + ":" + config.secret
        headers = {'Authorization': 'Basic ' + str(b64encode(s.encode("utf-8")), "utf-8")}
        data = {'grant_type': 'refresh_token', 'refresh_token': refreshToken}
        response = requests.post('https://identity.xero.com/connect/token', headers=headers, data=data)

        # try refreshing the token and if really expired, save the new refresh token to use later
        try:
            token = response.json()['access_token']
            refreshToken = response.json()['refresh_token']

            file = open('access_token', 'w')
            file.write(token)
            file.close()

            file = open('refreshToken', 'w')
            file.write(refreshToken)
            file.close()
        except:
            pass

        # get the optional start/end date parameters
        startdate = request.args.get('startdate', default=(datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d"))
        enddate = request.args.get('enddate', default=(datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d"))

        if startdate is None or enddate is None:
            startdate = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")  # yesterday
            enddate = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")  # yesterday

        # date range string to pass later to Xero API - add ACCREC clause for only invoices
        whereClause = f"Date >= DateTime({','.join(startdate.split('-'))}) AND Date <= DateTime({','.join(enddate.split('-'))})&&Type==\"ACCREC\""

        # call the Invoices API to get the data
        # using paging to enable getting the line items for each invoice
        # https://developer.xero.com/documentation/api/invoices
        i = 0
        invoices = []
        headpdf = {'Authorization': 'Bearer ' + token, 'xero-tenant-id': tenantId, 'Accept': 'application/pdf'}
        headjson = {'Authorization': 'Bearer ' + token, 'xero-tenant-id': tenantId, 'Accept': 'application/json'}
        while True:
            i += 1
            params = {'where': whereClause, 'page': i, 'Status': 'AUTHORISED'}
            response = requests.get('https://api.xero.com/api.xro/2.0/Invoices/', headers=headjson, params=params)
            try:
                if len(response.json()['Invoices']) == 0:
                    break
            except:
                break
            invoices += response.json()['Invoices']

        logging.info(f'Retrieving invoices from {startdate} to {enddate}, {str(len(invoices))} returned from Xero API')

        # create a folder
        # save each PDFs there and add a csv record for each invoice
        resultName = 'invoices ' + datetime.datetime.now().strftime("%d %b %Y %H-%M-%S")

        # Open the list with history of processed invoices
        processedInvoicesFileName = 'processed_invoices.json'
        if processedInvoicesFileName in os.listdir('.'):
            processedInvoices = json.load(open(processedInvoicesFileName))
        else:
            processedInvoices = []

        try:
            os.mkdir(resultName)
        except OSError:
            pass

        i = 0

        invoicesPerClient = {}
        for invoice in invoices:
            # Check if the invoice was processed earlier already
            if invoice['InvoiceID'] in processedInvoices:
                logging.info(f'Invoice {str(invoice["InvoiceID"])} was already processed, skipping it...')
                continue

            # Group invoices per client to send them together
            invoicesPerClient.setdefault(invoice['Contact']['ContactID'], [])
            invoicesPerClient[invoice['Contact']['ContactID']].append(invoice)

        for contactId in invoicesPerClient.keys():
            # Get the detailed contact information
            contactresponse = requests.get('https://api.xero.com/api.xro/2.0/Contacts/' + contactId, headers=headjson)
            contact = contactresponse.json()['Contacts'][0]

            # Get PDFs of each invoice for this client
            pdfMerger = PyPDF2.PdfFileMerger()
            for invoice in invoicesPerClient[contactId]:
                response = requests.get('https://api.xero.com/api.xro/2.0/Invoices/' + invoice['InvoiceID'], headers=headpdf, params=params)

                # Save each PDF as an individual file
                pdfFilePath = os.path.join('.', resultName, invoice['InvoiceID'] + '.pdf')
                file = open(pdfFilePath, 'wb')
                file.write(response.content)
                file.close()

                # Add this PDF's bytes to the merged PDF object
                pdfMerger.append(io.BytesIO(response.content))

            # Create a temporary file to write the merged PDF to
            tempFile = open('temp merged PDF file', 'wb')
            pdfMerger.write(tempFile)
            tempFile.close()

            # creating authorization credentials for LetterStream
            i += 1
            unique_id = str(i) + str(datetime.datetime.now().timestamp()).replace('.', '')[2:]
            string_to_hash = unique_id[-6:] + config.api_key + unique_id[:6]
            hash = hashlib.md5(base64.b64encode(string_to_hash.encode("utf-8"))).hexdigest()

            # requesting LetterStream API
            addresses = []
            a = 0

            for address in contact['Addresses']:
                if address['AddressType'] == 'POBOX':
                    a += 1
                    firstAddressLine = address.get('AddressLine1', '')
                    secondAddressLine = ' '.join([
                        address.get('AddressLine2', ''),
                        address.get('AddressLine3', ''),
                        address.get('AddressLine4', '')
                    ]).strip()
                    addresses.append(
                        f"{unique_id + str(a)}:{contact['Name']}::{firstAddressLine}:{secondAddressLine}:{address.get('City', '')}:{address.get('Region', '')}:{address.get('PostalCode', '')}")

            data = {
                'a': config.api_id,
                'h': hash,
                't': unique_id,
                'job': datetime.datetime.now().strftime("%y%m%d") + '-' + contact['Name'][0:8] + '-' + unique_id[-4:],
                'to[]': addresses,
                'from': config.fromAddress,
                'single_file': base64.b64encode(open('temp merged PDF file', 'rb').read()),
                'pages': str(PyPDF2.PdfFileReader(open('temp merged PDF file', 'rb')).numPages),
                'ink': config.Ink
            }

            res = requests.post('https://www.letterstream.com/apis/', data=data)
            res.raise_for_status()

            # Remove the temporary file
            os.remove('temp merged PDF file')

            # Log the processed invoices
            sentInvoices = []
            for invoice in invoicesPerClient[contactId]:
                sentInvoices.append(invoice['InvoiceID'])
            logging.info(f'Invoice(s) {", ".join(sentInvoices)} billed to client {contact["Name"]} successfully sent to Letterstream')

            # Save the processed invoice to avoid duplication
            processedInvoices += sentInvoices

        json.dump(processedInvoices, open(processedInvoicesFileName, 'w'))
    except:
        logging.error(traceback.format_exc())
        return Response(status=500)

    return Response(status=200)


@app.route(sfConfig['sf_auth_slug'])
def salesforce_authorization():
    # Salesforce OAuth 2.0 API reference:
    # https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_web_server_flow.htm&type=5

    # Update the log parameters with the new filename
    reportName = os.path.join('logs', 'log ' + datetime.datetime.now().strftime('%Y-%m') + '.txt')
    logging.basicConfig(filename=reportName, level=logging.INFO, format=' %(asctime)s -  %(levelname)s -  %(message)s')

    # Read the config file
    sfConfig = json.load(open(os.path.join(application_path, 'sf_config.json')))

    token = sfConfig.get('access_token')

    if token:
        logging.info('The app authorization url is called but the app is already authorized')
        return 'The app is already authorized'
    else:
        # Check if user returned from the authorization page with the code
        authCode = request.args.get('code')
        if authCode:
            # Send the code to get the access token
            data = {
                'grant_type': 'authorization_code',
                'code': authCode,
                'client_id': sfConfig["sf_consumer_key"],
                'client_secret': sfConfig["sf_consumer_secret"],
                'redirect_uri': sfConfig["app_address"] + sfConfig["sf_auth_slug"]
            }
            response = requests.post('https://godschild.lightning.force.com/services/oauth2/token', data=data)

            try:
                sfConfig['access_token'] = response.json()['access_token']
            except:
                logging.error(str(response.json()))
                raise Exception('error getting the token from the response')

            # Save the access token
            json.dump(sfConfig, open(os.path.join(application_path, 'sf_config.json'), 'w'))

            logging.info('The app got authorized')

            return f'The app is authorized.'

        else:
            # send the authorization request to get the code
            redirectUrl = f'https://login.salesforce.com/services/oauth2/authorize?' \
                          f'response_type=code&' \
                          f'client_id={sfConfig["sf_consumer_key"]}&' \
                          f'redirect_uri={sfConfig["app_address"]}{sfConfig["sf_auth_slug"]}&' \
                          f'scope=full'
            logging.info('The app authorization url is called, no token found. Redirecting to ' + redirectUrl)
            return redirect(redirectUrl)


@app.route('/')
def respond():
    return 'Hello world'
