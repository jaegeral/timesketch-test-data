Running inside the Timesketch-dev container:

```
/usr/local/src/timesketch/test_tools# python3 sigma_verify_rules.py --config_file ../data/sigma_config.yaml /etc/timesketch/data/sigma/ --move /usr/local/src/timesketch/pob
```

Produces:
```
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_global_catalog_enumeration.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_clip+_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_obfuscated_iex_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_stdin+_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_var+_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_via_compress_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_via_rundll_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_via_stdin_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_via_use_clip_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_via_use_mhsta_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_via_use_rundll32_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_invoke_obfuscation_via_var++_services.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_mal_creddumper.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_metasploit_or_impacket_smb_psexec_service_install.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_meterpreter_or_cobaltstrike_getsystem_service_installation.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_net_ntlm_downgrade.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_powershell_script_installed_as_service.yml: No condition found
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_rare_schtasks_creations.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_rare_service_installs.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_root_certificate_installed.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_software_discovery.yml: No condition found
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_susp_failed_logons_single_source.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_susp_samr_pwset.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/builtin/win_tap_driver_installation.yml: No condition found
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/file_event/win_susp_multiple_files_renamed_or_deleted.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Yaml parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/image_load/sysmon_in_memory_powershell.yml: while parsing a flow mapping
  in "<unicode string>", line 1, column 1:
    {'title': 'In-memory PowerShell' ... 
    ^
expected ',' or '}', but got '<scalar>'
  in "<unicode string>", line 1, column 236:
     ... shell.exe. Detects meterpreter\'s "load powershell" extension.', ... 
                                         ^
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/image_load/sysmon_mimikatz_inmemory_detection.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/image_load/sysmon_tttracer_mod_load.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/malware/win_mal_blue_mockingbird.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/network_connection/sysmon_regsvr32_network_activity.yml: No detection definitions found
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/other/win_rare_schtask_creation.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/other/win_tool_psexec.yml: No condition found
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/powershell/powershell_CL_Invocation_LOLScript_v2.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/powershell/powershell_CL_Mutexverifiers_LOLScript_v2.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/powershell/win_powershell_web_request.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_apt_chafer_mar18.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_apt_empiremonkey.yml: No condition found
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_apt_slingshot.yml: No condition found
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_apt_turla_commands.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_apt_unidentified_nov_18.yml: No condition found
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_dnscat2_powershell_implementation.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_mal_adwind.yml: No condition found
ERROR:timesketch.lib.sigma:Yaml parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_mouse_lock.yml: while parsing a flow mapping
  in "<unicode string>", line 1, column 1:
    {'title': 'Mouse Lock Credential ... 
    ^
expected ',' or '}', but got '<scalar>'
  in "<unicode string>", line 1, column 148:
     ... , 'description': 'In Kaspersky\'s 2020 Incident Response Analyst ... 
                                         ^
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_multiple_suspicious_cli.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_silenttrinity_stage_use.yml: No detection definitions found
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_susp_commands_recon_activity.yml: Aggregations not implemented for this backend
ERROR:timesketch.lib.sigma:Sigma parsing error generating rule in file /etc/timesketch/data/sigma/rules/windows/process_creation/win_syncappvpublishingserver_exe.yml: No condition found
ERROR:timesketch.lib.sigma:Error generating rule in file /etc/timesketch/data/sigma/rules/windows/sysmon/sysmon_possible_dns_rebinding.yml: Aggregations not implemented for this backend
```

Running analyzer produces the following errors with rules:

```
/rules/windows/sysmon/sysmon_suspicious_remote_thread.yml
/rules/windows/sysmon/sysmon_apt_turla_namedpipes.yml
/rules/windows/powershell/powershell_invoke_obfuscation_via_var%2B%2B.yml
```

```
Problematic rules:
* powershell_invoke_obfuscation_via_var++.yml
* sysmon_apt_turla_namedpipes.yml
* sysmon_suspicious_remote_thread.yml
```

```
[2021-04-11 12:52:29,077] timesketch.elasticsearch/ERROR Unable to run search query: [query_shard_exception] Failed to parse query [((EventID:"4104" AND ScriptBlockText.keyword:/(?i).*&&set.*(\\{\\d\\}){2,}\\\\\\"\\s+?\\-f.*&&.*cmd.*\\/c/c/) OR (EventID:"4103" AND Payload.keyword:/(?i).*&&set.*(\\{\\d\\}){2,}\\\\\\"\\s+?\\-f.*&&.*cmd.*\\/c/))]
Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 562, in search
    _search_result = self.client.search(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/utils.py", line 84, in _wrapped
    return func(*args, params=params, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/__init__.py", line 1547, in search
    return self.transport.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/transport.py", line 351, in perform_request
    status, headers_response, data = connection.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/http_urllib3.py", line 261, in perform_request
    self._raise_error(response.status, raw_data)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/base.py", line 181, in _raise_error
    raise HTTP_EXCEPTIONS.get(status_code, TransportError)(
elasticsearch.exceptions.RequestError: RequestError(400, 'search_phase_execution_exception', 'Failed to parse query [((EventID:"4104" AND ScriptBlockText.keyword:/(?i).*&&set.*(\\\\{\\\\d\\\\}){2,}\\\\\\\\\\\\"\\\\s+?\\\\-f.*&&.*cmd.*\\\\/c/c/) OR (EventID:"4103" AND Payload.keyword:/(?i).*&&set.*(\\\\{\\\\d\\\\}){2,}\\\\\\\\\\\\"\\\\s+?\\\\-f.*&&.*cmd.*\\\\/c/))]')
[2021-04-11 12:52:29,102] timesketch.analyzers.sigma_tagger/ERROR Problem with rule in file powershell_invoke_obfuscation_via_var++.yml: 
Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 562, in search
    _search_result = self.client.search(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/utils.py", line 84, in _wrapped
    return func(*args, params=params, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/__init__.py", line 1547, in search
    return self.transport.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/transport.py", line 351, in perform_request
    status, headers_response, data = connection.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/http_urllib3.py", line 261, in perform_request
    self._raise_error(response.status, raw_data)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/base.py", line 181, in _raise_error
    raise HTTP_EXCEPTIONS.get(status_code, TransportError)(
elasticsearch.exceptions.RequestError: RequestError(400, 'search_phase_execution_exception', 'Failed to parse query [((EventID:"4104" AND ScriptBlockText.keyword:/(?i).*&&set.*(\\\\{\\\\d\\\\}){2,}\\\\\\\\\\\\"\\\\s+?\\\\-f.*&&.*cmd.*\\\\/c/c/) OR (EventID:"4103" AND Payload.keyword:/(?i).*&&set.*(\\\\{\\\\d\\\\}){2,}\\\\\\\\\\\\"\\\\s+?\\\\-f.*&&.*cmd.*\\\\/c/))]')

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/sigma_tagger.py", line 67, in run
    tagged_events_counter = self.run_sigma_rule(
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/sigma_tagger.py", line 40, in run_sigma_rule
    for event in events:
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/interface.py", line 948, in event_stream
    for event in event_generator:
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 622, in search_stream
    result = self.search(
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 583, in search
    raise ValueError(cause) from e
ValueError: [query_shard_exception] Failed to parse query [((EventID:"4104" AND ScriptBlockText.keyword:/(?i).*&&set.*(\\{\\d\\}){2,}\\\\\\"\\s+?\\-f.*&&.*cmd.*\\/c/c/) OR (EventID:"4103" AND Payload.keyword:/(?i).*&&set.*(\\{\\d\\}){2,}\\\\\\"\\s+?\\-f.*&&.*cmd.*\\/c/))]
[2021-04-11 12:52:43,123] timesketch.analyzers.sigma_tagger/ERROR Timeout executing search for powershell_nishang_malicious_commandlets.yml: ConnectionTimeout caused by - ReadTimeoutError(HTTPConnectionPool(host='elasticsearch', port=9200): Read timed out. (read timeout=10)) waiting for 10 seconds
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 421, in _make_request
    six.raise_from(e, None)
  File "<string>", line 3, in raise_from
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 416, in _make_request
    httplib_response = conn.getresponse()
  File "/usr/lib/python3.8/http/client.py", line 1347, in getresponse
    response.begin()
  File "/usr/lib/python3.8/http/client.py", line 307, in begin
    version, status, reason = self._read_status()
  File "/usr/lib/python3.8/http/client.py", line 268, in _read_status
    line = str(self.fp.readline(_MAXLINE + 1), "iso-8859-1")
  File "/usr/lib/python3.8/socket.py", line 669, in readinto
    return self._sock.recv_into(b)
socket.timeout: timed out

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/http_urllib3.py", line 241, in perform_request
    response = self.pool.urlopen(
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 719, in urlopen
    retries = retries.increment(
  File "/usr/lib/python3/dist-packages/urllib3/util/retry.py", line 376, in increment
    raise six.reraise(type(error), error, _stacktrace)
  File "/usr/local/lib/python3.8/dist-packages/six.py", line 693, in reraise
    raise value
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 665, in urlopen
    httplib_response = self._make_request(
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 423, in _make_request
    self._raise_timeout(err=e, url=url, timeout_value=read_timeout)
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 330, in _raise_timeout
    raise ReadTimeoutError(
urllib3.exceptions.ReadTimeoutError: HTTPConnectionPool(host='elasticsearch', port=9200): Read timed out. (read timeout=10)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/sigma_tagger.py", line 67, in run
    tagged_events_counter = self.run_sigma_rule(
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/sigma_tagger.py", line 40, in run_sigma_rule
    for event in events:
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/interface.py", line 948, in event_stream
    for event in event_generator:
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 622, in search_stream
    result = self.search(
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 562, in search
    _search_result = self.client.search(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/utils.py", line 84, in _wrapped
    return func(*args, params=params, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/__init__.py", line 1547, in search
    return self.transport.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/transport.py", line 351, in perform_request
    status, headers_response, data = connection.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/http_urllib3.py", line 253, in perform_request
    raise ConnectionTimeout("TIMEOUT", str(e), e)
elasticsearch.exceptions.ConnectionTimeout: ConnectionTimeout caused by - ReadTimeoutError(HTTPConnectionPool(host='elasticsearch', port=9200): Read timed out. (read timeout=10))
[2021-04-11 12:53:32,546] timesketch.elasticsearch/ERROR Unable to run search query: [query_shard_exception] Failed to parse query [(EventID:("17" OR "18") AND PipeName:("\\atctl" OR "\\\userpipe" OR "\\iehelper" OR "\\sdlrpc" OR "\\comnap"))]
Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 562, in search
    _search_result = self.client.search(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/utils.py", line 84, in _wrapped
    return func(*args, params=params, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/__init__.py", line 1547, in search
    return self.transport.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/transport.py", line 351, in perform_request
    status, headers_response, data = connection.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/http_urllib3.py", line 261, in perform_request
    self._raise_error(response.status, raw_data)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/base.py", line 181, in _raise_error
    raise HTTP_EXCEPTIONS.get(status_code, TransportError)(
elasticsearch.exceptions.RequestError: RequestError(400, 'search_phase_execution_exception', 'Failed to parse query [(EventID:("17" OR "18") AND PipeName:("\\\\atctl" OR "\\\\\\userpipe" OR "\\\\iehelper" OR "\\\\sdlrpc" OR "\\\\comnap"))]')
[2021-04-11 12:53:32,547] timesketch.analyzers.sigma_tagger/ERROR Problem with rule in file sysmon_apt_turla_namedpipes.yml: 
Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 562, in search
    _search_result = self.client.search(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/utils.py", line 84, in _wrapped
    return func(*args, params=params, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/__init__.py", line 1547, in search
    return self.transport.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/transport.py", line 351, in perform_request
    status, headers_response, data = connection.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/http_urllib3.py", line 261, in perform_request
    self._raise_error(response.status, raw_data)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/base.py", line 181, in _raise_error
    raise HTTP_EXCEPTIONS.get(status_code, TransportError)(
elasticsearch.exceptions.RequestError: RequestError(400, 'search_phase_execution_exception', 'Failed to parse query [(EventID:("17" OR "18") AND PipeName:("\\\\atctl" OR "\\\\\\userpipe" OR "\\\\iehelper" OR "\\\\sdlrpc" OR "\\\\comnap"))]')

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/sigma_tagger.py", line 67, in run
    tagged_events_counter = self.run_sigma_rule(
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/sigma_tagger.py", line 40, in run_sigma_rule
    for event in events:
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/interface.py", line 948, in event_stream
    for event in event_generator:
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 622, in search_stream
    result = self.search(
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 583, in search
    raise ValueError(cause) from e
ValueError: [query_shard_exception] Failed to parse query [(EventID:("17" OR "18") AND PipeName:("\\atctl" OR "\\\userpipe" OR "\\iehelper" OR "\\sdlrpc" OR "\\comnap"))]
[2021-04-11 12:54:06,635] timesketch.elasticsearch/ERROR Unable to run search query: [query_shard_exception] Failed to parse query [((EventID:"8" AND SourceImage.keyword:(*\\bash.exe OR *\\cvtres.exe OR *\\defrag.exe OR *\\dnx.exe OR *\\esentutl.exe OR *\\excel.exe OR *\\expand.exe OR *\\explorer.exe OR *\\find.exe OR *\\findstr.exe OR *\\forfiles.exe OR *\\git.exe OR *\\gpupdate.exe OR *\\hh.exe OR *\\iexplore.exe OR *\\installutil.exe OR *\\lync.exe OR *\\makecab.exe OR *\\mDNSResponder.exe OR *\\monitoringhost.exe OR *\\msbuild.exe OR *\\mshta.exe OR *\\msiexec.exe OR *\\mspaint.exe OR *\\outlook.exe OR *\\ping.exe OR *\\powerpnt.exe OR *\\powershell.exe OR *\\provtool.exe OR *\\python.exe OR *\\regsvr32.exe OR *\\robocopy.exe OR *\\runonce.exe OR *\\sapcimc.exe OR *\\schtasks.exe OR *\\smartscreen.exe OR *\\spoolsv.exe OR *\\tstheme.exe OR *\\\userinit.exe OR *\\vssadmin.exe OR *\\vssvc.exe OR *\\w3wp.exe* OR *\\winlogon.exe OR *\\winscp.exe OR *\\wmic.exe OR *\\word.exe OR *\\wscript.exe)) AND (NOT (SourceImage.keyword:*Visual\ Studio*)))]
Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 562, in search
    _search_result = self.client.search(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/utils.py", line 84, in _wrapped
    return func(*args, params=params, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/__init__.py", line 1547, in search
    return self.transport.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/transport.py", line 351, in perform_request
    status, headers_response, data = connection.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/http_urllib3.py", line 261, in perform_request
    self._raise_error(response.status, raw_data)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/base.py", line 181, in _raise_error
    raise HTTP_EXCEPTIONS.get(status_code, TransportError)(
elasticsearch.exceptions.RequestError: RequestError(400, 'search_phase_execution_exception', 'Failed to parse query [((EventID:"8" AND SourceImage.keyword:(*\\\\bash.exe OR *\\\\cvtres.exe OR *\\\\defrag.exe OR *\\\\dnx.exe OR *\\\\esentutl.exe OR *\\\\excel.exe OR *\\\\expand.exe OR *\\\\explorer.exe OR *\\\\find.exe OR *\\\\findstr.exe OR *\\\\forfiles.exe OR *\\\\git.exe OR *\\\\gpupdate.exe OR *\\\\hh.exe OR *\\\\iexplore.exe OR *\\\\installutil.exe OR *\\\\lync.exe OR *\\\\makecab.exe OR *\\\\mDNSResponder.exe OR *\\\\monitoringhost.exe OR *\\\\msbuild.exe OR *\\\\mshta.exe OR *\\\\msiexec.exe OR *\\\\mspaint.exe OR *\\\\outlook.exe OR *\\\\ping.exe OR *\\\\powerpnt.exe OR *\\\\powershell.exe OR *\\\\provtool.exe OR *\\\\python.exe OR *\\\\regsvr32.exe OR *\\\\robocopy.exe OR *\\\\runonce.exe OR *\\\\sapcimc.exe OR *\\\\schtasks.exe OR *\\\\smartscreen.exe OR *\\\\spoolsv.exe OR *\\\\tstheme.exe OR *\\\\\\userinit.exe OR *\\\\vssadmin.exe OR *\\\\vssvc.exe OR *\\\\w3wp.exe* OR *\\\\winlogon.exe OR *\\\\winscp.exe OR *\\\\wmic.exe OR *\\\\word.exe OR *\\\\wscript.exe)) AND (NOT (SourceImage.keyword:*Visual\\ Studio*)))]')
[2021-04-11 12:54:06,636] timesketch.analyzers.sigma_tagger/ERROR Problem with rule in file sysmon_suspicious_remote_thread.yml: 
Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 562, in search
    _search_result = self.client.search(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/utils.py", line 84, in _wrapped
    return func(*args, params=params, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/client/__init__.py", line 1547, in search
    return self.transport.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/transport.py", line 351, in perform_request
    status, headers_response, data = connection.perform_request(
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/http_urllib3.py", line 261, in perform_request
    self._raise_error(response.status, raw_data)
  File "/usr/local/lib/python3.8/dist-packages/elasticsearch/connection/base.py", line 181, in _raise_error
    raise HTTP_EXCEPTIONS.get(status_code, TransportError)(
elasticsearch.exceptions.RequestError: RequestError(400, 'search_phase_execution_exception', 'Failed to parse query [((EventID:"8" AND SourceImage.keyword:(*\\\\bash.exe OR *\\\\cvtres.exe OR *\\\\defrag.exe OR *\\\\dnx.exe OR *\\\\esentutl.exe OR *\\\\excel.exe OR *\\\\expand.exe OR *\\\\explorer.exe OR *\\\\find.exe OR *\\\\findstr.exe OR *\\\\forfiles.exe OR *\\\\git.exe OR *\\\\gpupdate.exe OR *\\\\hh.exe OR *\\\\iexplore.exe OR *\\\\installutil.exe OR *\\\\lync.exe OR *\\\\makecab.exe OR *\\\\mDNSResponder.exe OR *\\\\monitoringhost.exe OR *\\\\msbuild.exe OR *\\\\mshta.exe OR *\\\\msiexec.exe OR *\\\\mspaint.exe OR *\\\\outlook.exe OR *\\\\ping.exe OR *\\\\powerpnt.exe OR *\\\\powershell.exe OR *\\\\provtool.exe OR *\\\\python.exe OR *\\\\regsvr32.exe OR *\\\\robocopy.exe OR *\\\\runonce.exe OR *\\\\sapcimc.exe OR *\\\\schtasks.exe OR *\\\\smartscreen.exe OR *\\\\spoolsv.exe OR *\\\\tstheme.exe OR *\\\\\\userinit.exe OR *\\\\vssadmin.exe OR *\\\\vssvc.exe OR *\\\\w3wp.exe* OR *\\\\winlogon.exe OR *\\\\winscp.exe OR *\\\\wmic.exe OR *\\\\word.exe OR *\\\\wscript.exe)) AND (NOT (SourceImage.keyword:*Visual\\ Studio*)))]')

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/sigma_tagger.py", line 67, in run
    tagged_events_counter = self.run_sigma_rule(
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/sigma_tagger.py", line 40, in run_sigma_rule
    for event in events:
  File "/usr/local/src/timesketch/timesketch/lib/analyzers/interface.py", line 948, in event_stream
    for event in event_generator:
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 622, in search_stream
    result = self.search(
  File "/usr/local/src/timesketch/timesketch/lib/datastores/elastic.py", line 583, in search
    raise ValueError(cause) from e
ValueError: [query_shard_exception] Failed to parse query [((EventID:"8" AND SourceImage.keyword:(*\\bash.exe OR *\\cvtres.exe OR *\\defrag.exe OR *\\dnx.exe OR *\\esentutl.exe OR *\\excel.exe OR *\\expand.exe OR *\\explorer.exe OR *\\find.exe OR *\\findstr.exe OR *\\forfiles.exe OR *\\git.exe OR *\\gpupdate.exe OR *\\hh.exe OR *\\iexplore.exe OR *\\installutil.exe OR *\\lync.exe OR *\\makecab.exe OR *\\mDNSResponder.exe OR *\\monitoringhost.exe OR *\\msbuild.exe OR *\\mshta.exe OR *\\msiexec.exe OR *\\mspaint.exe OR *\\outlook.exe OR *\\ping.exe OR *\\powerpnt.exe OR *\\powershell.exe OR *\\provtool.exe OR *\\python.exe OR *\\regsvr32.exe OR *\\robocopy.exe OR *\\runonce.exe OR *\\sapcimc.exe OR *\\schtasks.exe OR *\\smartscreen.exe OR *\\spoolsv.exe OR *\\tstheme.exe OR *\\\userinit.exe OR *\\vssadmin.exe OR *\\vssvc.exe OR *\\w3wp.exe* OR *\\winlogon.exe OR *\\winscp.exe OR *\\wmic.exe OR *\\word.exe OR *\\wscript.exe)) AND (NOT (SourceImage.keyword:*Visual\ Studio*)))]
```


