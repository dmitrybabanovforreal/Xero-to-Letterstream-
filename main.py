#! /usr/bin/python3

from flask import Flask, request, Response, redirect
import config
import requests, datetime, os, PyPDF2, base64, hashlib, json, io
from base64 import b64encode


app = Flask(__name__)

@app.route(config.authSlug)
def authorization():
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

            return f'The app is authorized. You can now call {config.appAddress}{config.invoicesSlug} to trigger the ' \
                   f'invoices processing.\n\nYou can pass startdate and enddate parameters in YYYY-MM-DD format to ' \
                   f'specify the invoices dates.\n\nBy default it processes all invoices generated yesterday'

        else:
            # todo specify the correct scope in the config file
            # send the authorization request to get the code
            # https://developer.xero.com/documentation/oauth2/auth-flow#authorize
            redirectUrl = f'https://login.xero.com/identity/connect/authorize?response_type=code&client_id={config.id}&redirect_uri={config.appAddress}{config.authSlug}&scope={config.scope}'
            return redirect(redirectUrl)


@app.route(config.invoicesSlug)
def process_invoices():
    # check that all the credentials are available
    try:
        token = open('token').read()
        refreshToken = open('refreshToken').read()
        tenantId = open('tenantId').read()
    except:
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

        # Save the processed invoice to avoid duplication
        for invoice in invoicesPerClient[contactId]:
            processedInvoices.append(invoice['InvoiceID'])

    json.dump(processedInvoices, open(processedInvoicesFileName, 'w'))
    return Response(status=200)


@app.route('/')
def respond():
    return 'Hello world'
