const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const msgTxt = document.querySelector(".message");
const loginBtn = document.querySelector(".login");
const regBtn = document.querySelector(".register");
const unameInput = document.querySelector(".username");

function displayMessage(msg) {
  msgTxt.innerHTML = msg;
}

async function myfetch(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    body: JSON.stringify(payload),
    headers: { "Content-Type": "application/json" },
  });

  const contentType = res.headers.get('content-type');
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Server error ${res.status}: ${text}`);
  }

  if (!contentType || !contentType.includes('application/json')) {
    const text = await res.text();
    throw new Error(`Expected JSON, got: ${text}`);
  }

  return res.json();
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
      displayMessage(`<pre>${JSON.stringify(verification, null, 2)}</pre>`);
    }
  } catch (error) {
    console.error(error);
    displayMessage(error.message || "Unknown error during registration");
  }
});

loginBtn.addEventListener("click", async () => {
  displayMessage("");

  try {
    const challenge = await myfetch("https://webauthn-node.onrender.com/login", { username: unameInput.value });

    const signedChallenge = await startAuthentication(challenge);
    localStorage.setItem('verification', JSON.stringify(signedChallenge));

    const verification = await myfetch("https://webauthn-node.onrender.com/login/complete", signedChallenge);

    if (verification?.verified) {
      displayMessage("Login Success!");
      localStorage.setItem('username', unameInput.value);
      window.location.href = "https://webauthn-node.onrender.com/loggedin.html";
    } else {
      displayMessage(`<pre>${JSON.stringify(verification, null, 2)}</pre>`);
    }
  } catch (error) {
    console.error(error);
    displayMessage(error.message || "Unknown error during login");
  }
});
