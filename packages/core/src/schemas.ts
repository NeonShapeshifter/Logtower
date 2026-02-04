import { z } from 'zod';

export const LogtowerEventSchema = z.object({
  timestamp: z.string(),
  host: z.string(),
  channel: z.string(),
  event_id: z.number(),
  user: z.object({
    name: z.string().optional().nullable(),
    domain: z.string().optional().nullable(),
    logon_type: z.union([z.string(), z.number()]).optional().nullable(),
  }).optional(),
  process: z.object({
    image: z.string().optional().nullable(),
    command_line: z.string().optional().nullable(),
    parent_image: z.string().optional().nullable(),
    pid: z.union([z.string(), z.number()]).optional().nullable(),
    target_image: z.string().optional().nullable(),
    source_image: z.string().optional().nullable(),
    start_function: z.string().optional().nullable(),
    start_address: z.string().optional().nullable(),
    granted_access: z.string().optional().nullable(),
    call_trace: z.string().optional().nullable(),
  }).optional(),
  network: z.object({
    src_ip: z.string().optional().nullable(),
    dst_ip: z.string().optional().nullable(),
    dst_port: z.union([z.string(), z.number()]).optional().nullable(),
  }).optional(),
  // New detection fields
  registry: z.object({
    target_object: z.string().optional().nullable(),
    details: z.string().optional().nullable(),
  }).optional(),
  service: z.object({
    image_path: z.string().optional().nullable(),
    service_name: z.string().optional().nullable(),
  }).optional(),
  task: z.object({
    action: z.string().optional().nullable(),
    task_name: z.string().optional().nullable(),
    xml: z.string().optional().nullable(),
  }).optional(),
  image_load: z.object({
    file_path: z.string().optional().nullable(),
    file_name: z.string().optional().nullable(),
  }).optional(),
  // New APT/Ransomware fields
  wmi: z.object({
    operation: z.string().optional().nullable(),
    destination: z.string().optional().nullable(),
    command_line: z.string().optional().nullable(),
    script_text: z.string().optional().nullable(),
    name: z.string().optional().nullable(),
    query: z.string().optional().nullable(),
    consumer: z.string().optional().nullable(),
    filter: z.string().optional().nullable(),
  }).optional(),
  ad_change: z.object({
    object_dn: z.string().optional().nullable(),
    attribute: z.string().optional().nullable(),
    class: z.string().optional().nullable(),
    value: z.string().optional().nullable(),
  }).optional(),
  pipe: z.object({
    name: z.string().optional().nullable(),
  }).optional(),
  group: z.object({
    name: z.string().optional().nullable(),
  }).optional(),
  // Sigma Compliance fields
  file: z.object({
    path: z.string().optional().nullable(),
    name: z.string().optional().nullable(),
  }).optional(),
  dns: z.object({
    query_name: z.string().optional().nullable(),
  }).optional(),
  // BITS fields
  bits: z.object({
    job_title: z.string().optional().nullable(),
    job_owner: z.string().optional().nullable(),
    file_name: z.string().optional().nullable(), // Local file
    url: z.string().optional().nullable(), // Remote URL
    client_app: z.string().optional().nullable(), // processPath equivalent
  }).optional(),
  // Directory Service Access fields (Event ID 4662)
  directory_service: z.object({
    object_type: z.string().optional().nullable(),
    properties: z.union([z.string(), z.array(z.string())]).optional().nullable(),
  }).optional(),
  // Identity fields
  kerberos: z.object({
    ticket_encryption: z.string().optional().nullable(),
    ticket_options: z.string().optional().nullable(),
    service_name: z.string().optional().nullable(),
    pre_auth_type: z.string().optional().nullable(),
    failure_code: z.string().optional().nullable(),
  }).optional(),
  auth: z.object({
    logon_guid: z.string().optional().nullable(),
    logon_type: z.union([z.string(), z.number()]).optional().nullable(),
    auth_package: z.string().optional().nullable(),
    workstation: z.string().optional().nullable(),
    failure_code: z.string().optional().nullable(),
  }).optional(),
  raw: z.record(z.string(), z.any()).optional(),
});

export type LogtowerEvent = z.infer<typeof LogtowerEventSchema>;

export const FindingSchema = z.object({
  id: z.string(),
  rule_id: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
  title: z.string(),
  description: z.string(),
  host: z.string(),
  timestamp: z.string(),
  score: z.number(),
  evidence: z.array(z.object({
    event_ts: z.string(),
    summary: z.string(),
    raw_event: z.record(z.string(), z.any()).optional(), // Added raw context
  })),
  mitre: z.array(z.string()).optional(),
  // Bubbled up context from primary evidence (the first event that triggered the finding)
  process: z.object({
    image: z.string().optional().nullable(),
    command_line: z.string().optional().nullable(),
    parent_image: z.string().optional().nullable(),
    pid: z.union([z.string(), z.number()]).optional().nullable(),
    target_image: z.string().optional().nullable(),
    source_image: z.string().optional().nullable(),
    granted_access: z.string().optional().nullable(),
    start_function: z.string().optional().nullable(),
    start_address: z.string().optional().nullable(),
  }).optional(),
  user: z.object({
      name: z.string().optional().nullable(),
      domain: z.string().optional().nullable(),
      target_name: z.string().optional().nullable(),
  }).optional(),
  // Bubble up new contexts
  registry: z.object({
    target_object: z.string().optional().nullable(),
    details: z.string().optional().nullable(),
  }).optional(),
  service: z.object({
    image_path: z.string().optional().nullable(),
    service_name: z.string().optional().nullable(),
  }).optional(),
  task: z.object({
    action: z.string().optional().nullable(),
    task_name: z.string().optional().nullable(),
    xml: z.string().optional().nullable(),
  }).optional(),
  image_load: z.object({
    file_path: z.string().optional().nullable(),
    file_name: z.string().optional().nullable(),
  }).optional(),
  // New finding fields for bubbling
  wmi: z.object({
    destination: z.string().optional().nullable(),
    operation: z.string().optional().nullable(),
    consumer: z.string().optional().nullable(),
    filter: z.string().optional().nullable(),
    query: z.string().optional().nullable(),
  }).optional(),
  ad_change: z.object({
    object_dn: z.string().optional().nullable(),
    attribute: z.string().optional().nullable(),
    value: z.string().optional().nullable(),
    class: z.string().optional().nullable(),
  }).optional(),
  pipe: z.object({
    name: z.string().optional().nullable(),
  }).optional(),
  file: z.object({
    path: z.string().optional().nullable(),
    name: z.string().optional().nullable(),
  }).optional(),
  dns: z.object({
    query_name: z.string().optional().nullable(),
  }).optional(),
  bits: z.object({
    job_title: z.string().optional().nullable(),
    url: z.string().optional().nullable(),
    file_name: z.string().optional().nullable(),
    client_app: z.string().optional().nullable(),
  }).optional(),
  kerberos: z.object({
    service_name: z.string().optional().nullable(),
    failure_code: z.string().optional().nullable(),
  }).optional(),
  directory_service: z.object({
    object_type: z.string().optional().nullable(),
    properties: z.union([z.string(), z.array(z.string())]).optional().nullable(),
  }).optional(),
  intel: z.object({
      match: z.boolean(),
      type: z.enum(['IP', 'HASH', 'DOMAIN', 'URL']).optional(),
      source: z.string().optional(),
      description: z.string().optional(),
      value: z.string().optional()
  }).optional(),
});

export type Finding = z.infer<typeof FindingSchema>;
