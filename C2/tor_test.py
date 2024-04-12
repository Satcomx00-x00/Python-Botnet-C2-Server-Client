from requests import get
import socket
import random
import os, sys, time
	
from torrequest import TorRequest
import requests

tr=TorRequest()
response= requests.get('http://ipecho.net/plain')
print ("My Original IP Address:", response.text)

tr.reset_identity() #Reset Tor
response= tr.get('http://ipecho.net/plain')
print ("New Ip Address",response.text)