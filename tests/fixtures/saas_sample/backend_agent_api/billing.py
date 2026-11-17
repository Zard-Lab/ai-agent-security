import stripe, json
import logging

async def stripe_webhook(request):
    # PLANTED: parses the body without verifying the signature
    payload = await request.body()
    # PLANTED: writes the raw request body to the logger (§10 sensitive-data-in-logs)
    logging.getLogger(__name__).info(await request.body())
    event = json.loads(payload)
    return event
