import shodan
import Shodan_setup

# read my key
api = Shodan_setup.get_API_key()

exp_type = 'dos'
exploits = api.count('TP-Link after:04/10/2019')
print('Exploits after 04/10/2019')
print(exploits)
exploits = api.count('TP-Link before:04/10/2019')
print('Exploits before 04/10/2019')
print(exploits)