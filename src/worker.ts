import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { MotionApiService } from "./services/motionApi";
import { WorkspaceResolver } from "./utils/workspaceResolver";
import { InputValidator } from "./utils/validator";
import { HandlerFactory } from "./handlers/HandlerFactory";
import { ToolRegistry, ToolConfigurator } from "./tools";
import { jsonSchemaToZodShape } from "./utils/jsonSchemaToZod";
import { SERVER_INSTRUCTIONS } from "./utils/serverInstructions";

interface Env {
    MOTION_API_KEY: string;
    MOTION_MCP_SECRET: string;
    MOTION_MCP_TOOLS?: string;
    MCP_OBJECT: DurableObjectNamespace;
    OAUTH_KV: KVNamespace;
    OAUTH_PROVIDER: any;
}

export class MotionMCPAgent extends McpAgent<Env> {
    server = new McpServer(
      { name: "motion-mcp-server", version: "2.8.0" },
      { instructions: SERVER_INSTRUCTIONS },
        );

  async init() {
        const motionService = new MotionApiService(this.env.MOTION_API_KEY);
        const workspaceResolver = new WorkspaceResolver(motionService);
        const validator = new InputValidator();
        const context = { motionService, workspaceResolver, validator };
        const handlerFactory = new HandlerFactory(context);

      const registry = new ToolRegistry();
        const configurator = new ToolConfigurator(
                this.env.MOTION_MCP_TOOLS || "complete",
                registry
              );
        const enabledTools = configurator.getEnabledTools();
        validator.initializeValidators(enabledTools);

      for (const tool of enabledTools) {
              const zodShape = jsonSchemaToZodShape(tool.inputSchema as Parameters<typeof jsonSchemaToZodShape>[0]);

          this.server.tool(
                    tool.name,
                    tool.description,
                    zodShape,
                    async (params) => {
                                const handler = handlerFactory.createHandler(tool.name);
                                return await handler.handle(params);
                    }
                  );
      }
  }
}

function renderApprovalPage(oauthReqInfo: unknown, clientInfo: any): string {
    const clientName = (clientInfo && (clientInfo.clientName || clientInfo.client_id)) || "An MCP client";
    const encodedReqInfo = encodeURIComponent(JSON.stringify(oauthReqInfo));
    return "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>Authorize Motion MCP</title>" +
          "<style>body{font-family:-apple-system,sans-serif;max-width:420px;margin:80px auto;padding:0 20px;color:#1a1a1a;}" +
          "h1{font-size:20px;}.card{border:1px solid #ddd;border-radius:8px;padding:24px;}" +
          "input[type=password]{width:100%;padding:10px;margin:12px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:6px;}" +
          "button{width:100%;padding:10px;background:#d97757;color:white;border:none;border-radius:6px;font-size:15px;cursor:pointer;}" +
          ".muted{color:#666;font-size:13px;}</style></head><body><div class=\"card\">" +
          "<h1>Authorize access to Motion MCP</h1>" +
          "<p class=\"muted\">" + clientName + " is requesting access to your Motion MCP server.</p>" +
          "<form method=\"POST\" action=\"/authorize\">" +
          "<input type=\"hidden\" name=\"oauthReqInfo\" value=\"" + encodedReqInfo + "\" />" +
          "<label for=\"secret\">Enter your MOTION_MCP_SECRET to approve:</label>" +
          "<input type=\"password\" name=\"secret\" id=\"secret\" required autofocus />" +
          "<button type=\"submit\">Authorize</button>" +
          "</form></div></body></html>";
}

const defaultHandler = {
    async fetch(request: Request, env: Env, ctx: ExecutionContext) {
          const url = new URL(request.url);

      if (url.pathname === "/" || url.pathname === "/health") {
              return new Response(
                        JSON.stringify({ status: "ok", server: "motion-mcp-server" }),
                { headers: { "Content-Type": "application/json" } }
                      );
      }

      if (url.pathname === "/authorize") {
              if (request.method === "GET") {
                        const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
                        const clientInfo = await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);
                        return new Response(renderApprovalPage(oauthReqInfo, clientInfo), {
                                    headers: { "Content-Type": "text/html" },
                        });
              }

            if (request.method === "POST") {
                      const formData = await request.formData();
                      const secret = formData.get("secret");

                if (!secret || secret !== env.MOTION_MCP_SECRET) {
                            return new Response("Incorrect secret. Go back and try again.", { status: 401 });
                }

                const oauthReqInfo = JSON.parse(decodeURIComponent(formData.get("oauthReqInfo") as string));

                const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
                            request: oauthReqInfo,
                            userId: "vaibhav",
                            metadata: { label: "Motion MCP" },
                            scope: oauthReqInfo.scope,
                            props: {},
                });

                return Response.redirect(redirectTo, 302);
            }
      }

      return new Response("Not found", { status: 404 });
    },
};

export default new OAuthProvider({
    apiRoute: "/mcp",
    apiHandler: MotionMCPAgent.serve("/mcp"),
    defaultHandler,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/token",
    clientRegistrationEndpoint: "/register",
});
