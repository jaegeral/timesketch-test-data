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
