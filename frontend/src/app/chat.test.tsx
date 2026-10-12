// @vitest-environment jsdom
import {afterEach,expect,it,vi} from "vitest";
import {cleanup,fireEvent,render,screen} from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import Chat from "./chat";

afterEach(()=>{cleanup();localStorage.clear();vi.unstubAllGlobals()});
function mockChat(failPost=false){
 localStorage.setItem("agentguard_session","session-1");
 const calls:{url:string;init?:RequestInit}[]=[];
 const action={action_id:"action-1",task_id:"task-1",executed:true,timestamp:"2026-10-13T10:00:00Z",agent_id:"agent",session_id:"session-1",tool:"calculator",arguments:{expression:"44*55"},target_resource:null,result_summary:"{\"result\":2420}",status:"allowed",decision:"allow",reason:"safe arithmetic",duration_ms:3.5,risk_score:2,risk_probability:.02,model_version:"local",related_action_id:null,approval_id:null};
 const detail={task_id:"task-1",session_id:"session-1",task:"Calculate 44 * 55.",status:"completed",answer:"44 times 55 is 2420.",error:null,created_at:"2026-10-13T10:00:00Z",updated_at:"2026-10-13T10:00:01Z",duration_ms:1000,analytics:{total_actions:1,allowed:1,blocked:0,review_required:0,failed:0,highest_risk_score:2,average_risk_score:2,tools_used:["calculator"]},actions:[action],security_events:[{event_id:1,action_id:"action-1",event_type:"allowed",decision:"allow",reason:"safe arithmetic",timestamp:"2026-10-13T10:00:00Z",tool:"calculator",risk_score:2}]};
 vi.stubGlobal("fetch",vi.fn(async(input:RequestInfo|URL,init?:RequestInit)=>{const url=String(input);calls.push({url,init});if(url.endsWith("/health"))return new Response(JSON.stringify({status:"ok"}),{status:200});if(url.endsWith("/agent/status"))return new Response(JSON.stringify({status:"ready",provider:"ollama",model:"llama3.2:3b"}),{status:200});if(url.includes("/sessions/session-1/tasks"))return new Response("[]",{status:200});if(url.endsWith("/tasks")&&init?.method==="POST")return failPost?new Response(JSON.stringify({detail:"Ollama unavailable"}),{status:503}):new Response(JSON.stringify({...detail,analytics:undefined,actions:undefined}),{status:202});if(url.includes("/tasks/task-1"))return new Response(JSON.stringify(detail),{status:200});return new Response("{}",{status:200})}));return {calls,detail};
}
it("renders chat prompts, submits a task, and shows actual persisted actions and analytics",async()=>{
 const {calls,detail}=mockChat();render(<Chat/>);const input=await screen.findByRole("textbox",{name:"Task for the agent"});fireEvent.change(input,{target:{value:detail.task}});fireEvent.keyDown(input,{key:"Enter",code:"Enter"});await screen.findByText("44 times 55 is 2420.");expect(calls.some(c=>c.url.endsWith("/tasks")&&c.init?.method==="POST")).toBe(true);expect(screen.getAllByText("2",{selector:"b"})).toHaveLength(2);expect(screen.getAllByText("calculator")).toHaveLength(2);expect(screen.getByText("safe arithmetic")).toBeInTheDocument();
});
it("clicks an example prompt and exposes backend task submission errors",async()=>{
 mockChat(true);render(<Chat/>);fireEvent.click(await screen.findByRole("button",{name:/Calculate 44 \* 55/}));expect(screen.getByRole("textbox",{name:"Task for the agent"})).toHaveValue("Calculate 44 * 55.");fireEvent.click(screen.getByRole("button",{name:/Send task/}));expect(await screen.findByRole("alert")).toHaveTextContent("Ollama unavailable");
});
