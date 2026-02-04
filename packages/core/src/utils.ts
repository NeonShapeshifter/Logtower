import { Finding, LogtowerEventSchema } from './schemas.js';
import path from 'path';

// ... (existing exports)

export function normalizeEvent(raw: any): any {
    try {
        // 1. Handle already-normalized or synthetic events
        if (raw.event_id !== undefined && raw.timestamp && raw.host) {
            const event: any = {
                user: {},
                process: {},
                network: {},
                registry: {},
                service: {},
                task: {},
                pipe: {},
                group: {},
                file: {},
                dns: {},
                kerberos: {},
                bits: {},
                auth: {},
                ...raw
            };
            return LogtowerEventSchema.parse(event);
        }

        // 2. Handle Rust Parser output: { Event: { System: ..., EventData: ... } }
        const sys = raw.Event?.System;
        const data = raw.Event?.EventData || {};
        
        if (!sys) return null;

        const eventId = typeof sys.EventID === 'object' ? parseInt(sys.EventID['#text'] || sys.EventID) : parseInt(sys.EventID);
        const timestamp = sys.TimeCreated?.['#attributes']?.SystemTime || new Date().toISOString();
        const host = sys.Computer || 'unknown';
        const channel = sys.Channel || 'unknown';

        const event: any = {
            timestamp,
            host,
            channel,
            event_id: eventId,
            user: {},
            process: {},
            network: {},
            registry: {},
            service: {},
            task: {},
            pipe: {},
            group: {},
            file: {},
            dns: {},
            kerberos: {},
            bits: {},
            auth: {},
            raw: data // Preserves EVERYTHING from EventData
        };

        // Normalization Logic 
        
        // BITS Events (Channel Check)
        if (channel === "Microsoft-Windows-Bits-Client/Operational") {
             // 3: Created, 4: Transferred, 59: Started, 60: Stopped
             if ([3, 4, 59, 60].includes(eventId)) {
                 event.bits.job_title = data.jobTitle || data.name; // name in some versions
                 event.bits.job_owner = data.jobOwner;
                 event.bits.file_name = data.fileLocalName || data.name; // fileLocalName in 60
                 event.bits.url = data.fileUrl || data.url; // fileUrl in 60
                 event.bits.client_app = data.processPath; // The process requesting the transfer
                 event.user.name = data.jobOwner;
                 // Map process info if available
                 if (data.processPath) {
                     event.process.image = data.processPath;
                     event.process.pid = data.processId;
                 }
             }
        }

        // PowerShell ScriptBlock (4104)
        else if (eventId === 4104) {
            // Map ScriptBlockText to command_line so existing rules work on script content
            event.process.command_line = data.ScriptBlockText;
            event.process.image = "powershell.exe"; // Virtual image context
            // UserID is often in System.Security.UserID attribute
            if (raw.Event.System.Security && raw.Event.System.Security['#attributes']) {
                event.user.name = raw.Event.System.Security['#attributes'].UserID;
            }
        }
        
        // Process Creation (1, 4688)
        if (eventId === 1 || eventId === 4688) {
            event.process.image = data.Image || data.NewProcessName;
            event.process.command_line = data.CommandLine;
            event.process.parent_image = data.ParentImage || data.ParentProcessName;
            event.process.pid = data.ProcessId || data.NewProcessId;
            event.user.name = data.User || data.SubjectUserName;
            event.user.domain = data.SubjectDomainName;
        }
        
        // Network (3)
        else if (eventId === 3) {
            event.process.image = data.Image;
            event.network.src_ip = data.SourceIp;
            event.network.dst_ip = data.DestinationIp;
            event.network.dst_port = data.DestinationPort;
            event.user.name = data.User;
        }

        // Logon (4624)
        else if (eventId === 4624) {
            event.user.name = data.TargetUserName;
            event.user.domain = data.TargetDomainName;
            event.user.logon_type = data.LogonType;
            event.network.src_ip = data.IpAddress;
            event.auth.logon_type = data.LogonType;
            event.auth.logon_guid = data.LogonGuid;
            event.auth.auth_package = data.AuthenticationPackageName;
            event.auth.workstation = data.WorkstationName;
        }

        // Logon Failure (4625)
        else if (eventId === 4625) {
            event.user.name = data.TargetUserName;
            event.network.src_ip = data.IpAddress;
            event.auth.failure_code = data.SubStatus || data.Status; // Often Status or SubStatus
        }
        
        // Image Load (7)
        else if (eventId === 7) {
            event.process.image = data.Image;
            event.image_load.file_path = data.ImageLoaded;
            event.image_load.file_name = data.OriginalFileName || (data.ImageLoaded ? data.ImageLoaded.split('\\').pop() : '');
        }

        // File Creation (11)
        else if (eventId === 11) {
            event.process.image = data.Image;
            event.file.path = data.TargetFilename;
            event.file.name = data.TargetFilename ? data.TargetFilename.split('\\').pop() : '';
        }

        // Process Access (10)
        else if (eventId === 10) {
             event.process.image = data.SourceImage;
             event.process.target_image = data.TargetImage;
             event.process.granted_access = data.GrantedAccess;
             event.process.call_trace = data.CallTrace;
        }

        // Registry (12, 13, 14)
        else if (eventId >= 12 && eventId <= 14) {
            event.process.image = data.Image;
            event.registry.target_object = data.TargetObject;
            event.registry.details = data.Details;
        }

        // Pipe Created / Connected (17, 18)
        else if (eventId === 17 || eventId === 18) {
            event.process.image = data.Image;
            event.pipe.name = data.PipeName;
        }

        // CreateRemoteThread (8)
        else if (eventId === 8) {
            event.process.source_image = data.SourceImage;
            event.process.target_image = data.TargetImage;
            event.process.start_function = data.StartFunction;
            event.process.start_address = data.StartAddress;
            event.process.pid = data.SourceProcessId; // Source PID context
        }

        // WMI Event (19, 20, 21)
        else if (eventId >= 19 && eventId <= 21) {
            event.user.name = data.User;
            event.wmi.operation = data.Operation;
            event.wmi.name = data.Name;
            
            // 19: Filter
            if (eventId === 19) {
                event.wmi.query = data.Query;
            }
            // 20: Consumer
            else if (eventId === 20) {
                event.wmi.destination = data.Destination; // Script or Command
                event.wmi.command_line = data.Destination; // Map for generic CLI rules
                event.wmi.script_text = data.Destination;  // Map for script rules
            }
            // 21: Binding
            else if (eventId === 21) {
                event.wmi.consumer = data.Consumer;
                event.wmi.filter = data.Filter;
            }
        }

        // Directory Service Change (5136)
        else if (eventId === 5136) {
            event.ad_change = {}; // Initialize if needed or rely on default
            event.ad_change.object_dn = data.ObjectDN;
            event.ad_change.attribute = data.AttributeLDAPDisplayName;
            event.ad_change.class = data.ObjectClass;
            event.ad_change.value = data.AttributeValue;
            event.user.name = data.SubjectUserName;
        }

        // DNS Query (22)
        else if (eventId === 22) {
            event.process.image = data.Image;
            event.dns.query_name = data.QueryName;
            event.user.name = data.User;
        }

        // Kerberos (4768 - TGT, 4769 - TGS, 4771 - PreAuth Fail)
        else if (eventId === 4768 || eventId === 4769 || eventId === 4771) {
            event.user.name = data.TargetUserName;
            event.network.src_ip = data.IpAddress;
            event.kerberos.ticket_encryption = data.TicketEncryptionType;
            event.kerberos.ticket_options = data.TicketOptions;
            event.kerberos.service_name = data.ServiceName;
            event.kerberos.failure_code = data.FailureCode || data.Status || data.ResultCode; // 4771 uses Status, 4769 uses FailureCode/Status
            event.kerberos.pre_auth_type = data.PreAuthType;
        }

        // Service Install (7045, 4697)
        else if (eventId === 7045 || eventId === 4697) {
            event.service.service_name = data.ServiceName;
            event.service.image_path = data.ImagePath;
        }

        // Scheduled Task (4698)
        else if (eventId === 4698) {
            event.task.task_name = data.TaskName;
            event.task.xml = JSON.stringify(data); // Capture full XML/Data for content matching
        }

        // Directory Service Access (4662)
        else if (eventId === 4662) {
            event.user.name = data.SubjectUserName;
            event.user.domain = data.SubjectDomainName;
            event.directory_service.object_type = data.ObjectType;
            // Properties can be a single GUID or comma-separated GUIDs
            const props = data.Properties;
            if (props) {
                // If it's a comma-separated string, split it into an array
                event.directory_service.properties = typeof props === 'string' && props.includes(',')
                    ? props.split(',').map((p: string) => p.trim())
                    : props;
            }
        }

        // User Account Management (4720, 4722, etc)
        else if (eventId >= 4720 && eventId <= 4738) {
            event.user.name = data.SubjectUserName; // Actor
            event.user.target_name = data.TargetUserName; // Victim
            event.group.name = data.GroupName || data.TargetUserName; // 4732 uses TargetUserName usually or GroupName depending on OS version
        }

        // Object Access (4663 - An attempt was made to access an object)
        else if (eventId === 4663) {
            event.process.image = data.ProcessName;
            event.process.granted_access = data.AccessMask;
            event.user.name = data.SubjectUserName;
            
            const objType = data.ObjectType;
            const objName = data.ObjectName;

            if (objType === 'File' || (typeof objName === 'string' && (objName.includes('\\') || objName.includes('.')))) {
                event.file.path = objName;
                event.file.name = objName.split('\\').pop();
                // Special case: LSASS Access via File Object (sometimes mapped this way)
                if (event.file.name.toLowerCase() === 'lsass.exe') {
                    event.process.target_image = objName;
                }
            } else if (objType === 'Key') {
                event.registry.target_object = objName;
            }
        }

        return LogtowerEventSchema.parse(event);
    } catch (e) {
        return null;
    }
}


export const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

export const getSampleEvidence = (f: Finding): string => {
  if (!f.evidence || f.evidence.length === 0) return "No evidence";
  
  const latest = f.evidence[f.evidence.length - 1];
  const raw = latest.raw_event || {};
  
  // 1. Sysmon 7 (Image Load)
  if (raw['ImageLoaded']) {
    const proc = raw['Image'] ? raw['Image'].split('\\').pop() : 'Process';
    const lib = raw['ImageLoaded'].split('\\').pop();
    return `${proc} loaded ${lib}`;
  }

  // 2. Command Line
  if (raw['CommandLine']) {
      const cmd = raw['CommandLine'];
      return cmd.length > 50 ? cmd.substring(0, 47) + '...' : cmd;
  }
  
  // 3. Registry
  if (raw['TargetObject']) {
      const type = raw['EventType'] || 'Registry';
      const val = raw['TargetObject'];
      const displayVal = val.length > 40 ? '...' + val.slice(-40) : val;
      return `${type}: ${displayVal}`;
  }

  // 4. File Events
  if (raw['TargetFilename']) {
      const val = raw['TargetFilename'];
      return `File: ...${val.slice(-40)}`;
  }

  // 4624: Logon
  if (raw['TargetUserName'] && raw['LogonType']) {
      return `User: ${raw['TargetUserName']} (Type ${raw['LogonType']}) from ${raw['IpAddress'] || 'local'}`;
  }
  
  // Fallback
  return latest.summary;
};

export const sortFindings = (findings: Finding[]): Finding[] => {
    return [...findings].sort((a, b) => {
        const sevDiff = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
        if (sevDiff !== 0) return sevDiff;
        // Recency (Newest first)
        const timeA = new Date(a.evidence[a.evidence.length-1]?.event_ts || 0).getTime();
        const timeB = new Date(b.evidence[b.evidence.length-1]?.event_ts || 0).getTime();
        return timeB - timeA;
    });
};

export type FilterMode = 'CRITICAL' | 'HIGH' | 'IMPORTANT' | 'ALL';

export const filterFindings = (findings: Finding[], mode: FilterMode): Finding[] => {
    return findings.filter(f => {
        if (mode === 'ALL') return true;
        if (mode === 'CRITICAL') return f.severity === 'CRITICAL';
        if (mode === 'HIGH') return ['CRITICAL', 'HIGH'].includes(f.severity);
        // IMPORTANT = Medium+
        return ['CRITICAL', 'HIGH', 'MEDIUM'].includes(f.severity);
    });
};
