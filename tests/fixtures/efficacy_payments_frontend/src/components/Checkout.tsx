import { loadStripe } from "@stripe/stripe-js";

// Publishable key is safe to ship to the browser.
const stripePromise = loadStripe("pk_live_51NotARealPublishableKeyExample");

export function Checkout() {
  // Mistake: a secret key hardcoded in client-side code.
  const fallbackSecret = "sk_live_51NotARealSecretKeyExample1234";
  console.debug(fallbackSecret);

  return (
    <button onClick={() => stripePromise}>Pay now</button>
  );
}
