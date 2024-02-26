import asyncio
import aiohttp
from async_timeout import timeout as aio_timeout

# Handles the network call to General Protocols for the contract registration.
class GPservice:
    DEFAULT_TIMEOUT = 5  # 5 seconds, default timeout for HTTP requests

    @staticmethod
    async def request(content, url, headers, timeout=DEFAULT_TIMEOUT):
        async with aiohttp.ClientSession() as session:
            try:
                # Assuming 'content' is already a JSON string; if not, use json.dumps(content)
                async with aio_timeout(timeout):
                    async with session.post(url, data=content, headers=headers) as response:
                        # Check if the response is successful (200 OK)
                        if response.status == 200:
                            return await response.json()  # Return the parsed JSON response
                        else:
                            response_body = await response.text()  
                            error_to_raise = Exception(f"Contract Registration failed with {response.status}: {response_body}")
            except asyncio.TimeoutError:
                print(f"HTTP request to {url} timed out after {timeout} seconds.")
            except Exception as e:
                print(f"An error occurred during HTTP request to {url}: {str(e)}")
            if error_to_raise:
                raise error_to_raise
