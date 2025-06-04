from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.common.by import By
import time

# FireFox profile
profile = webdriver.FirefoxProfile('/firefox/obj-x86_64-pc-linux-gnu/tmp/profile-default')
# Default Empty FireFox profile
# profile = webdriver.FirefoxProfile()

# FireFox Options
options = Options()
options.log.level = "trace"
options.add_argument("-headless")
options.binary_location = "/firefox/obj-x86_64-pc-linux-gnu/dist/bin/firefox"
options.profile = profile
gecko_log = '/geckodriver.log'

firefox_service = Service(
        executable_path="/usr/bin/geckodriver", 
        log_output=gecko_log, 
        service_args=['--log', 'debug'])

driver = webdriver.Firefox(options=options, service=firefox_service)
extension_path = '/tmp/extension.xpi'
driver.install_addon(extension_path, temporary=True)

# list of tuples of (url, dict of id and expected value pairs)
test_configs = [
    ("https://127.0.0.1:1443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "tls13.localhost",
        "tls-protocol": "TLSv1.3",
        "ssl-cipher": "TLS_AES_256_GCM_SHA384",
        "ssl_session_reused": ".",
        "server-port": "1443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:1443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "tls13.localhost",
        "tls-protocol": "TLSv1.3",
        "ssl-cipher": "TLS_AES_256_GCM_SHA384",
        "ssl_session_reused": "r",
        "server-port": "1443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:2443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "tls12.localhost",
        "tls-protocol": "TLSv1.2",
        "ssl-cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "ssl_session_reused": ".",
        "server-port": "2443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:2443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "tls12.localhost",
        "tls-protocol": "TLSv1.2",
        "ssl-cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "ssl_session_reused": "r",
        "server-port": "2443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:3443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "both.localhost",
        "tls-protocol": "TLSv1.3",
        "ssl-cipher": "TLS_AES_256_GCM_SHA384",
        "ssl_session_reused": ".",
        "server-port": "3443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:3443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "both.localhost",
        "tls-protocol": "TLSv1.3",
        "ssl-cipher": "TLS_AES_256_GCM_SHA384",
        "ssl_session_reused": "r",
        "server-port": "3443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:4443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "dualcert.localhost",
        "tls-protocol": "TLSv1.3",
        "ssl-cipher": "TLS_AES_256_GCM_SHA384",
        "ssl_session_reused": ".",
        "server-port": "4443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:4443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "dualcert.localhost",
        "tls-protocol": "TLSv1.3",
        "ssl-cipher": "TLS_AES_256_GCM_SHA384",
        "ssl_session_reused": "r",
        "server-port": "4443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:5443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "allciphers.localhost",
        "tls-protocol": "TLSv1.2",
        "ssl-cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "ssl_session_reused": ".",
        "server-port": "5443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:5443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "allciphers.localhost",
        "tls-protocol": "TLSv1.2",
        "ssl-cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "ssl_session_reused": "r",
        "server-port": "5443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:6443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "tls13ecc.localhost",
        "tls-protocol": "TLSv1.3",
        "ssl-cipher": "TLS_AES_256_GCM_SHA384",
        "ssl_session_reused": ".",
        "server-port": "6443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:6443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "tls13ecc.localhost",
        "tls-protocol": "TLSv1.3",
        "ssl-cipher": "TLS_AES_256_GCM_SHA384",
        "ssl_session_reused": "r",
        "server-port": "6443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:7443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "tls12ecc.localhost",
        "tls-protocol": "TLSv1.2",
        "ssl-cipher": "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ssl_session_reused": ".",
        "server-port": "7443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
    ("https://127.0.0.1:7443", {
        "wolfExtensionHeader": "wolfPKCS11 module found",
        "server-name": "tls12ecc.localhost",
        "tls-protocol": "TLSv1.2",
        "ssl-cipher": "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ssl_session_reused": "r",
        "server-port": "7443",
        "remote-addr": "127.0.0.1",
        "ssl-alpn-protocol": "http/1.1",
    }),
]

previous_url = None
for url, expected in test_configs:
    print(f"Testing {url}")
    # If its the same url as last iter, we just need to refresh the page
    if url == previous_url:
        driver.refresh()
    else:
        driver.get(url)
    previous_url = url
    for id, expected in expected.items():
        element = driver.find_element(By.ID, id)
        value = element.get_attribute("innerHTML")
        assert value == expected, f"Expected '{expected}' for '{id}' but got '{value}'"
        print(f"Test passed for {id}: {value}")

print("All tests completed.")
# Close the browser
driver.quit()