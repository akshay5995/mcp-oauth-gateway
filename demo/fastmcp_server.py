from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext


class UserAuthMiddleware(Middleware):
    """Simple middleware that checks for x-user-email header."""

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        if context.fastmcp_context is not None:
            headers = context.fastmcp_context.get_http_request().headers
            print(headers)

            # Check for x-user-email header
            user_email = None
            for header_name, header_value in headers.raw:
                if header_name.decode().lower() == "x-user-email":
                    user_email = header_value.decode()
                    break

            if not user_email:
                raise ToolError("Authentication required")

        result = await call_next(context)
        return result


def get_user_email(ctx: Context) -> str:
    """Get user email from headers."""
    headers = ctx.get_http_request().headers
    for header_name, header_value in headers.raw:
        if header_name.decode().lower() == "x-user-email":
            return header_value.decode()
    return "unknown@example.com"


# For Docker containers, specify host settings
mcp = FastMCP(name="CalculatorServer", host="0.0.0.0")
mcp.add_middleware(UserAuthMiddleware())


@mcp.tool
def add(a: int, b: int, ctx: Context) -> int:
    """Adds two integer numbers together."""
    result = a + b
    return result


@mcp.tool
def multiply(a: int, b: int, ctx: Context) -> int:
    """Multiplies two integer numbers together."""
    result = a * b
    return result


if __name__ == "__main__":
    # For Docker containers, specify host explicitly and use the /mcp/ path
    mcp.run(
        transport="http", 
        host="0.0.0.0",  # Critical for Docker - bind to all interfaces
        port=3001, 
        path="/mcp/",    # FastMCP serves at /mcp/ path by default
        log_level="debug"
    )
