// @vitest-environment jsdom
import {afterEach,expect,it,vi} from "vitest";
import * as React from "react";
import {cleanup,fireEvent,render,screen,waitFor} from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import Home from "./page";

afterEach(()=>{cleanup();sessionStorage.clear();localStorage.clear();vi.unstubAllGlobals()});
function mockApi(overrides:Record<string,unknown>={}){
 const calls:{url:string;init?:RequestInit}[]=[];
 vi.stubGlobal("fetch",vi.fn(async(input:RequestInfo|URL,init?:RequestInit)=>{
  const url=String(input);calls.push({url,init});let payload:unknown={};
  if(url.includes("/health"))payload={status:"ok",database:"ok",model:{status:"ready",model_version:"test-model",selected_model:"forest"}};
  else if(url.includes("/stats"))payload={total_actions:4,allowed:2,blocked:1,failed:0,review_required:1,security_incidents:2};
  else if(url.includes("/actions"))payload={items:[],total:0,limit:10,offset:0};
  else if(url.includes("/events"))payload={items:[],total:0,limit:50,offset:0};
  else if(url.includes("/model"))payload={status:"unavailable",model_version:null,selected_model:null,error:"absent",metadata:null,metrics:null,warning:null};
  else if(url.includes("/sessions"))payload={items:[]};
  else if(url.includes("/settings"))payload={allow_max:30,review_max:70};
  else if(url.includes("/approvals/pending"))payload={items:[]};
  for(const [needle,value] of Object.entries(overrides))if(url.includes(needle))payload=value;
  return new Response(JSON.stringify(payload),{status:200,headers:{"Content-Type":"application/json"}});
 }));return calls;
}
it("renders metrics from the real API response and honest missing-model state",async()=>{
 mockApi();render(<Home/>);expect(await screen.findByText("4")).toBeInTheDocument();expect(screen.getByText("Security incidents").parentElement).toHaveTextContent("2");fireEvent.click(screen.getByRole("button",{name:/model & evaluation/i}));expect(await screen.findByText(/Evaluation unavailable or model artifact not present/)).toBeInTheDocument();
});
it("shows explicit empty data state",async()=>{mockApi();render(<Home/>);fireEvent.click(screen.getByRole("button",{name:/actions$/i}));expect(await screen.findByText("No actions match this view yet.")).toBeInTheDocument()});
it("reports backend errors instead of presenting success metrics",async()=>{vi.stubGlobal("fetch",vi.fn().mockRejectedValue(new Error("network offline")));render(<Home/>);expect(await screen.findByRole("alert")).toHaveTextContent("Backend unavailable");});
it("shows a loading state while the initial API request is pending",()=>{vi.stubGlobal("fetch",vi.fn(()=>new Promise(()=>{})));render(<Home/>);expect(screen.getByRole("status")).toHaveTextContent("Loading live dashboard data")});
it("filters actions locally by search",async()=>{
 const action={action_id:"a-1",timestamp:"2026-10-12T10:00:00Z",agent_id:"agent",session_id:"sess",tool:"calculator",arguments:{expression:"2+2"},target_resource:null,result_summary:"4",status:"allowed",decision:"allow",reason:"safe calculation",duration_ms:2,risk_score:5,risk_probability:.05,model_version:"m",related_action_id:null,approval_id:null};
 mockApi({"/actions":{items:[action],total:1,limit:10,offset:0}});render(<Home/>);fireEvent.click(screen.getByRole("button",{name:/actions$/i}));expect(await screen.findByText("calculator")).toBeInTheDocument();fireEvent.change(screen.getByRole("textbox",{name:"Search actions"}),{target:{value:"missing"}});await waitFor(()=>expect(screen.getByText("No actions match this view yet.")).toBeInTheDocument());
});
it("requests the next page and status filters from the API",async()=>{
 const calls=mockApi({"/actions":{items:[],total:12,limit:10,offset:0}});render(<Home/>);fireEvent.click(screen.getByRole("button",{name:/actions$/i}));fireEvent.change(screen.getByRole("combobox",{name:"Filter by status"}),{target:{value:"blocked"}});await waitFor(()=>expect(calls.some(c=>c.url.includes("status=blocked"))).toBe(true));fireEvent.click(screen.getByRole("button",{name:"Next"}));await waitFor(()=>expect(calls.some(c=>c.url.includes("offset=10")&&c.url.includes("status=blocked"))).toBe(true));
});
it("sends real rejection decision with approver credential",async()=>{
 sessionStorage.setItem("agentguard_approver","test-review-key");
 const approval={approval_id:"ap-1",action_id:"a-1",tool:"read_file",arguments:{filename:"private.txt"},target_resource:"private.txt",risk_score:55,created_at:"2026-10-12T10:00:00Z",expires_at:"2026-10-12T11:00:00Z",status:"pending",session_id:"s-test",reason:"risk requires review",history:[]};
 const calls=mockApi({"/approvals/pending":{items:[approval]},"/approvals/ap-1":{approval_id:"ap-1",status:"rejected",executed:false}});render(<Home/>);fireEvent.click(screen.getByRole("button",{name:/approvals/i}));fireEvent.click(await screen.findByRole("button",{name:"Reject"}));await waitFor(()=>expect(calls.some(c=>c.url.endsWith("/approvals/ap-1")&&c.init?.method==="POST")).toBe(true));const call=calls.find(c=>c.url.endsWith("/approvals/ap-1"))!;expect(JSON.parse(String(call.init?.body))).toEqual({decision:"reject",approver_id:"local-reviewer"});expect(new Headers(call.init?.headers).get("X-Approver-Token")).toBe("test-review-key");expect(await screen.findByText(/Execution: not performed/)).toBeInTheDocument();
});
it("sends approval to FastAPI and reports only its execution result",async()=>{
 sessionStorage.setItem("agentguard_approver","test-review-key");
 const approval={approval_id:"ap-2",action_id:"a-2",tool:"calculator",arguments:{expression:"2+2",api_key:"example-secret"},target_resource:null,risk_score:55,created_at:"2026-10-12T10:00:00Z",expires_at:"2026-10-12T11:00:00Z",status:"pending",session_id:"s-test",reason:"requires review",history:[]};
 const calls=mockApi({"/approvals/pending":{items:[approval]},"/approvals/ap-2":{approval_id:"ap-2",status:"allowed",executed:true}});render(<Home/>);fireEvent.click(screen.getByRole("button",{name:/approvals/i}));fireEvent.click(await screen.findByRole("button",{name:"Approve and revalidate"}));await waitFor(()=>expect(calls.some(c=>c.url.endsWith("/approvals/ap-2")&&c.init?.method==="POST")).toBe(true));const call=calls.find(c=>c.url.endsWith("/approvals/ap-2"))!;expect(JSON.parse(String(call.init?.body))).toEqual({decision:"approve",approver_id:"local-reviewer"});expect(new Headers(call.init?.headers).get("X-Approver-Token")).toBe("test-review-key");expect(screen.queryByText("example-secret")).not.toBeInTheDocument();expect(await screen.findByText(/Execution: performed/)).toBeInTheDocument();
});
