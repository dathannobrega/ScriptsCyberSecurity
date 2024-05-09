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

def consultar_abuseipdb(ip):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    try:
        response = requests.get(f'https://www.abuseipdb.com/check/{ip}', headers=headers)
        response.raise_for_status()  # Isso assegura que erros HTTP lançam exceções
        return response.text  # Retorna o HTML da página
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
    api_key = config['API_KEYS']['VIRUSTOTAL_API_KEY']

    if len(sys.argv) < 2:
        print("Usage: python infoIP.py <ip>")
        sys.exit(1)

    ip = sys.argv[1]

    #virus_total_result = consultar_ip_virustotal(ip, api_key)
    abuseipdb_result = consultar_abuseipdb(ip)
    print(abuseipdb_result)
    #ibm_xforce_result = consultar_ibm_xforce(ip)
    #whois_result = consultar_whois(ip)

    #gerar_relatorio(ip, virus_total_result, abuseipdb_result, ibm_xforce_result, whois_result)

    print("Relatório gerado com sucesso!")


if __name__ == "__main__":
    main()
