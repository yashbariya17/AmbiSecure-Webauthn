const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const msgTxt = document.querySelector(".message");
const loginBtn = document.querySelector(".login");
const regBtn = document.querySelector(".register");
const unameInput = document.querySelector(".username");

function displayMessage(msg) {
  msgTxt.innerHTML = msg;
}

async function myfetch(url, payload) {
  return await fetch(url, {
    method: "POST",
    body: JSON.stringify(payload),
    headers: { "Content-Type": "application/json" },
  }).then((res) => res.json());
}

regBtn.addEventListener("click", async () => {


  displayMessage("");

  const challenge = await myfetch("https://webauthn-node.onrender.com/register", { username: unameInput.value });

  let signedChallenge;
  try {
    signedChallenge = await startRegistration(challenge);
  } catch (error) {
    displayMessage(error);
    throw error;
  }

  const verification = await myfetch("https://webauthn-node.onrender.com/register/complete", signedChallenge);

  if (verification?.verified) {
    displayMessage("Success!");
  } else {
    displayMessage(`<pre>${JSON.stringify(verification)}</pre>`);
  }
});

loginBtn.addEventListener("click", async () => {
  displayMessage("");
  const challenge = await myfetch("/login", { username: unameInput.value });

  let signedChallenge;
  try {
    signedChallenge = await startAuthentication(challenge);
    localStorage.setItem('verification', JSON.stringify(signedChallenge));
  } catch (error) {
    displayMessage(error);
    throw error;
  }

  const verification = await myfetch("/login/complete", signedChallenge);

  if (verification?.verified) {
    displayMessage("Success!");
    // Store the username and verification data in localStorage before redirecting
    localStorage.setItem('username', unameInput.value);
    window.location.href = "https://webauthn-node.onrender.com/loggedin.html";
  } else {
    displayMessage(`<pre>${JSON.stringify(verification)}</pre>`);
  }
}); 
