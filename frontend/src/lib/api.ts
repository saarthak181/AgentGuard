export const API_URL = (typeof window === "undefined" ? process.env.NEXT_PUBLIC_AGENTGUARD_API : localStorage.getItem("agentguard_api")) || "http://127.0.0.1:8000";
export async function api<T>(path:string, options:RequestInit={}):Promise<T>{
  const headers = new Headers(options.headers); headers.set("Content-Type","application/json");
  if(typeof window!=="undefined"){const token=sessionStorage.getItem("agentguard_approver"); if(token)headers.set("X-Approver-Token",token);}
  let response:Response;
  try{response=await fetch(`${API_URL}${path}`,{...options,headers,cache:"no-store"});}
  catch{throw new Error(`Cannot reach AgentGuard API at ${API_URL}. Start the backend and confirm the URL in Settings.`);}
  if(!response.ok){let detail=`API request failed (${response.status})`; try{const body=await response.json();detail=body.detail||detail;}catch{} throw new Error(detail);}
  return response.json() as Promise<T>;
}
export type RiskAssessment={policy_version:string;inherent_risk:number;contextual_risk:number;behavioral_risk:number;ml_risk:number;final_risk_score:number;formula:string};
export type Action={action_id:string;timestamp:string;agent_id:string;session_id:string;task_id:string|null;executed:boolean;tool:string;arguments:Record<string,unknown>;target_resource:string|null;result_summary:string;status:string;decision:string;reason:string;duration_ms:number;risk_score:number|null;risk_probability:number|null;model_version:string|null;assessment?:RiskAssessment|null;related_action_id:string|null;approval_id:string|null};
export type Page<T>={items:T[];total:number;limit:number;offset:number};
export type TaskSummary={task_id:string;session_id:string;task:string;status:string;answer:string|null;error:string|null;created_at:string;updated_at:string;duration_ms:number|null};
export type TaskAnalytics={total_actions:number;allowed:number;blocked:number;review_required:number;failed:number;highest_risk_score:number|null;average_risk_score:number|null;tools_used:string[]};
export type TaskSecurityEvent={event_id:number;action_id:string;event_type:string;decision:string;reason:string;timestamp:string;tool:string;risk_score:number|null};
export type TaskDetail=TaskSummary&{analytics:TaskAnalytics;actions:Action[];security_events:TaskSecurityEvent[]};
export function safeJson(value:unknown):string { return JSON.stringify(value,(key,val)=>/password|passwd|secret|token|api[_-]?key|authorization|credential/i.test(key)?"[REDACTED]":typeof val==="string"?val.replace(/(bearer\s+)[\w.~+/=-]+/ig,"$1[REDACTED]").replace(/(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+/ig,"$1=[REDACTED]"):val,2); }
