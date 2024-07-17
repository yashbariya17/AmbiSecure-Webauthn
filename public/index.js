const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const msgTxt = document.querySelector(".message");
const loginBtn = document.querySelector(".login");
const regBtn = document.querySelector(".register");
const unameInput = document.querySelector(".username");

function displayMessage(msg) {
  msgTxt.innerHTML = msg;
}

async function myfetch(url, payload) {
  try {
    const response = await fetch(url, {
      method: "POST",
      body: JSON.stringify(payload),
      headers: { "Content-Type": "application/json" },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    return response.json();

  } catch (error) {
    console.error("Fetch error:", error);
    throw error;
  }
}

regBtn.addEventListener("click", async () => {
  displayMessage("");

  try {
    const challenge = await myfetch("https://webauthn-node.onrender.com/register", { username: unameInput.value });
    const signedChallenge = await startRegistration(challenge);

    const verification = await myfetch("https://webauthn-node.onrender.com/register/complete", signedChallenge);

    if (verification?.verified) {
      displayMessage("Registration Success!");
    } else {
      displayMessage(`<pre>${JSON.stringify(verification)}</pre>`);
    }

  } catch (error) {
    displayMessage(error.message);
  }
});

loginBtn.addEventListener("click", async () => {
  displayMessage("");

  try {
    const challenge = await myfetch("https://webauthn-node.onrender.com/login", { username: unameInput.value });
    const signedChallenge = await startAuthentication(challenge);

    const verification = await myfetch("https://webauthn-node.onrender.com/login/complete", signedChallenge);

    if (verification?.verified) {
      displayMessage("Login Success!");
    } else {
      displayMessage(`<pre>${JSON.stringify(verification)}</pre>`);
    }

  } catch (error) {
    displayMessage(error.message);
  }
});
