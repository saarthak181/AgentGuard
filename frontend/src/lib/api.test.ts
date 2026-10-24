import {afterEach,describe,expect,it,vi} from "vitest";
import {api,safeJson} from "./api";
afterEach(()=>vi.unstubAllGlobals());
describe("typed API client",()=>{
 it("returns live API response data",async()=>{vi.stubGlobal("fetch",vi.fn().mockResolvedValue(new Response(JSON.stringify({total_actions:8}),{status:200})));await expect(api<{total_actions:number}>("/stats")).resolves.toEqual({total_actions:8})});
 it("surfaces backend errors rather than inventing success",async()=>{vi.stubGlobal("fetch",vi.fn().mockResolvedValue(new Response(JSON.stringify({detail:"database unavailable"}),{status:503})));await expect(api("/health")).rejects.toThrow("database unavailable")});
 it("turns browser connection failures into a useful startup instruction",async()=>{vi.stubGlobal("fetch",vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));await expect(api("/health")).rejects.toThrow("Cannot reach AgentGuard API at http://127.0.0.1:8000")});
 it("redacts secrets recursively and credential strings",()=>{const result=safeJson({password:"hunter2",nested:{api_key:"abc"},note:"Bearer token123"});expect(result).not.toContain("hunter2");expect(result).not.toContain("abc");expect(result).not.toContain("token123");expect(result).toContain("[REDACTED]")});
});
