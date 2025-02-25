import subprocess
import os
import re
import configparser
import time
import logging
import json

from urllib.parse import urlparse

config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini')
config = configparser.ConfigParser()
config.read(config_path)


NUCLEI_SEVERITY_MAP = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'unknown': -1,
}

def remove_ansi_escape_sequences(text):
	# Regular expression to match ANSI escape sequences
	ansi_escape_pattern = r'\x1b\[.*?m'

	plain_text = re.sub(ansi_escape_pattern, '', text)
	return plain_text


def run_command(
		cmd, 
		cwd=None, 
		shell=False, 
		history_file=None, 
		remove_ansi_sequence=False
	):
	"""Run a given command using subprocess module.

	Args:
		cmd (str): Command to run.
		cwd (str): Current working directory.
		echo (bool): Log command.
		shell (bool): Run within separate shell if True.
		history_file (str): Write command + output to history file.
		remove_ansi_sequence (bool): Used to remove ANSI escape sequences from output such as color coding
	Returns:
		tuple: Tuple with return_code, output.
	"""
	# Create a command record in the database


	# Run the command using subprocess
	popen = subprocess.Popen(
		cmd if shell else cmd.split(),
		shell=shell,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		cwd=cwd,
		universal_newlines=True)
	output = ''
	for stdout_line in iter(popen.stdout.readline, ""):
		item = stdout_line.strip()
		output += '\n' + item
	popen.stdout.close()
	popen.wait()
	return_code = popen.returncode

	if history_file:
		mode = 'a'
		if not os.path.exists(history_file):
			mode = 'w'
		with open(history_file, mode) as f:
			f.write(f'\n{cmd}\n{return_code}\n{output}\n------------------\n')
	if remove_ansi_sequence:
		output = remove_ansi_escape_sequences(output)
    
	return return_code, output


def stream_command(cmd, cwd=None, shell=False, history_file=None, encoding='utf-8', scan_id=None, activity_id=None, trunc_char=None):
	logging.info(cmd)
	
	command = cmd if shell else cmd.split()

	process = subprocess.Popen(
		command,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		universal_newlines=True,
		shell=shell)

	output = ""

	for line in iter(lambda: process.stdout.readline(), b''):
		if not line:
			break
		line = line.strip()
		ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
		line = ansi_escape.sub('', line)
		line = line.replace('\\x0d\\x0a', '\n')
		if trunc_char and line.endswith(trunc_char):
			line = line[:-1]
		item = line

		try:
			item = json.loads(line)
		except json.JSONDecodeError:
			pass

		yield item

		output += line + "\n"


	process.wait()
	return_code = process.returncode


	if history_file is not None:
		with open(history_file, "a") as f:
			f.write(f"{cmd}\n{return_code}\n{output}\n")


def sanitize_url(http_url):
	"""Removes HTTP ports 80 and 443 from HTTP URL.

	Args:
		http_url (str): Input HTTP URL.

	Returns:
		str: Stripped HTTP URL.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in http_url:
		http_url = "http://" + http_url
	url = urlparse(http_url)

	if url.netloc.endswith(':80'):
		url = url._replace(netloc=url.netloc.replace(':80', ''))
	elif url.netloc.endswith(':443'):
		url = url._replace(scheme=url.scheme.replace('http', 'https'))
		url = url._replace(netloc=url.netloc.replace(':443', ''))
	return url.geturl().rstrip('/')


def get_subdomain_from_url(url):
	"""Get subdomain from HTTP URL.

	Args:
		url (str): HTTP URL.

	Returns:
		str: Subdomain name.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in url:
		url = "http://" + url

	url_obj = urlparse(url.strip())
	return url_obj.netloc.split(':')[0]


def get_alive_endpoint():
    return 0
    
#=======================================================================================================================
def parse_nuclei_result(line):
	"""Parse results from nuclei JSON output.

	Args:
		line (dict): Nuclei JSON line output.

	Returns:
		dict: Vulnerability data.
	"""
	return {
		'name': line['info'].get('name', ''),
		'type': line['type'],
		'severity': NUCLEI_SEVERITY_MAP[line['info'].get('severity', 'unknown')],
		'template': line['template'],
		'template_url': line['template-url'],
		'template_id': line['template-id'],
		'description': line['info'].get('description', ''),
		'matcher_name': line.get('matcher-name', ''),
		'curl_command': line.get('curl-command'),
		'request': line.get('request'),
		'response': line.get('response'),
		'extracted_results': line.get('extracted-results', []),
		'cvss_metrics': line['info'].get('classification', {}).get('cvss-metrics', ''),
		'cvss_score': line['info'].get('classification', {}).get('cvss-score'),
		'cve_ids': line['info'].get('classification', {}).get('cve_id', []) or [],
		'cwe_ids': line['info'].get('classification', {}).get('cwe_id', []) or [],
		'references': line['info'].get('reference', []) or [],
		'tags': line['info'].get('tags', []),
		'source': "NUCLEI",
	}


def nuclei_scan(urls=[], ctx={}, description=None):
	"""HTTP vulnerability scan using Nuclei

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.

	Notes:
	Unfurl the urls to keep only domain and path, will be sent to vuln scan and
	ignore certain file extensions. Thanks: https://github.com/six2dez/reconftw
	"""
	input_path = f'result/all_domain.txt'
	# input_path = f'vulns/input_endpoints_vulnerability_scan.txt'
	concurrency = config.getint('NUCLEI', 'threads')
	rate_limit = config.getint('NUCLEI', 'rate_limit')
	retries = config.getint('NUCLEI','retry')
	timeout = config.getint('NUCLEI','timeout')
	nuclei_template_path = config.get('NUCLEI','templates_path') 
	severities = list(NUCLEI_SEVERITY_MAP.keys())
	nuclei_templates = config.get('NUCLEI','templates_path')
	custom_nuclei_templates = config.get('NUCLEI','custom_templates')
	severities_str = ','.join(severities)
	
 	# Get alive endpoints
	# if urls:
	# 	with open(input_path, 'w') as f:
	# 		f.write('\n'.join(urls))
	# else:
	# 	get_http_urls(
	# 		is_alive=enable_http_crawl,
	# 		ignore_files=True,
	# 		write_filepath=input_path,
	# 		ctx=ctx
	# 	)


	logging.info('Updating Nuclei templates ...')
    
	run_command(
		'nuclei -update-templates',
		shell=True)
	templates = []
	templates.append(nuclei_template_path)


	if custom_nuclei_templates != '':
		templates.extend(custom_nuclei_templates)

	cmd = 'nuclei -j'
	cmd += f' -irr'
	cmd += f' -l {input_path}'
	cmd += f' -c {str(concurrency)}' if concurrency > 0 else ''
	cmd += f' -retries {retries}' if retries > 0 else ''
	cmd += f' -rl {rate_limit}' if rate_limit > 0 else ''
	cmd += f' -timeout {str(timeout)}' if timeout and timeout > 0 else ''
	cmd += f' -silent'
	for tpl in templates:
		cmd += f' -t {tpl}'


	grouped_tasks = []
	custom_ctx = ctx
	for severity in severities:
		custom_ctx['track'] = True
		_task = nuclei_individual_severity_module(
			cmd,
			'high',
			ctx=custom_ctx,
			description=f'Nuclei Scan with severity {severity}'
		)
		grouped_tasks.append(_task)

	# celery_group = group(grouped_tasks)
	# job = celery_group.apply_async()

	# while not job.ready():
	# 	time.sleep(5)

	logging.info('Vulnerability scan with all severities completed...')

	return None


def nuclei_individual_severity_module(cmd, severity, ctx={}, description=None):
	'''
		This celery task will run vulnerability scan in parallel.
		All severities supplied should run in parallel as grouped tasks.
	'''
	results = []
	logging.info(f'Running vulnerability scan with severity: {severity}')
	cmd += f' -severity {severity}'

	for line in stream_command(cmd):

		if not isinstance(line, dict):
			continue

		results.append(line)

		vuln_data = parse_nuclei_result(line)

		http_url = sanitize_url(line.get('matched-at'))
		subdomain_name = get_subdomain_from_url(http_url)



		# Look for duplicate vulnerabilities by excluding records that might change but are irrelevant.
		object_comparison_exclude = ['response', 'curl_command', 'tags', 'references', 'cve_ids', 'cwe_ids']

		# Add subdomain and target domain to the duplicate check
		# vuln_data_copy = vuln_data.copy()
		# vuln_data_copy['subdomain'] = subdomain
		# vuln_data_copy['target_domain'] = self.domain



		# # Get or create EndPoint object
		# response = line.get('response')
		# httpx_crawl = False if response else enable_http_crawl # avoid yet another httpx crawl
		# endpoint, _ = save_endpoint(
		# 	http_url,
		# 	crawl=httpx_crawl,
		# 	subdomain=subdomain,
		# 	ctx=ctx)
		# if endpoint:
		# 	http_url = endpoint.http_url
		# 	if not httpx_crawl:
		# 		output = parse_curl_output(response)
		# 		endpoint.http_status = output['http_status']
		# 		endpoint.save()

		# vuln, _ = save_vulnerability(
		# 	target_domain=self.domain,
		# 	http_url=http_url,
		# 	scan_history=self.scan,
		# 	subscan=self.subscan,
		# 	subdomain=subdomain,
		# 	**vuln_data)
		# if not vuln:
		# 	continue

		# severity = line['info'].get('severity', 'unknown')
		# logging.warning(str(vuln))


		
	# with open(self.output_path, 'w') as f:
	# 	json.dump(results, f, indent=4)




nuclei_scan()