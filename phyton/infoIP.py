import ssl
import configparser
import sys
import ipaddress
from fpdf import FPDF
from urllib3.util.ssl_ import create_urllib3_context
import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup


class SSLClientAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
        super(SSLClientAdapter, self).init_poolmanager(*args, ssl_context=context, **kwargs)

session = requests.Session()
session.mount('https://', SSLClientAdapter())

def consultar_ip_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    try:
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def consultar_abuseipdb(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": ""
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Isso assegura que erros HTTP lançam exceções
        return response.json()  # Retorna o JSON da resposta
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def consultar_ibm_xforce(ip):
    url = f"https://exchange.xforce.ibmcloud.com/ip/{ip}"
    return url

def consultar_whois(ip):
    try:
        # Validar o IP
        ipaddress.ip_address(ip)  # Isso lançará um ValueError se não for um IP válido
        w = whois.whois(ip)
        return dict(w)
    except ValueError as ve:
        return {"error": f"Erro ao consultar o WHOIS: {str(ve)}"}
    except Exception as e:
        return {"error": f"Erro ao consultar o WHOIS: {str(e)}"}

def gerar_relatorio(ip, virus_total_result, abuseipdb_result, ibm_xforce_result, whois_result):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt=f"Relatório de Consulta para o IP: {ip}", ln=True, align="C")
    pdf.ln(10)

    pdf.cell(200, 10, txt="Detalhes da consulta no VirusTotal:", ln=True)
    pdf.multi_cell(0, 10, txt=str(virus_total_result))
    pdf.ln(10)

    pdf.cell(200, 10, txt="Resultado da consulta no AbuseIPDB:", ln=True)
    pdf.multi_cell(0, 10, txt=str(abuseipdb_result))
    pdf.ln(10)

    pdf.cell(200, 10, txt=f"Link para consulta no IBM X-Force: {ibm_xforce_result}", ln=True)
    pdf.ln(10)

    pdf.cell(200, 10, txt="Detalhes da consulta WHOIS:", ln=True)
    pdf.multi_cell(0, 10, txt=str(whois_result))
    pdf.ln(10)

    pdf.output(f"relatorio_{ip}.pdf")

def main():
    config = configparser.ConfigParser()
    config.read('config.ini')
    api_key_VT = config['API_KEYS']['VIRUSTOTAL_API_KEY']
    api_key_AIPDB = config['API_KEYS']['ABUSEIPDB_API_KEY']

    if len(sys.argv) < 2:
        print("Usage: python infoIP.py <ip>")
        sys.exit(1)

    ip = sys.argv[1]

    #virus_total_result = consultar_ip_virustotal(ip, api_key_VT)
    abuseipdb_result = consultar_abuseipdb(ip, api_key_AIPDB)
    print(abuseipdb_result)
    #ibm_xforce_result = consultar_ibm_xforce(ip)
    #whois_result = consultar_whois(ip)

    #gerar_relatorio(ip, virus_total_result, abuseipdb_result, ibm_xforce_result, whois_result)

    print("Relatório gerado com sucesso!")


if __name__ == "__main__":
    main()
