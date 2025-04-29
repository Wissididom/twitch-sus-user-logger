import "dotenv/config";
import * as readline from "readline";

export async function getUser(clientId, accessToken, login) {
  let apiUrl = login
    ? `https://api.twitch.tv/helix/users?login=${login}`
    : `https://api.twitch.tv/helix/users`;
  let userResponse = await fetch(apiUrl, {
    headers: {
      "Client-ID": clientId,
      Authorization: `Bearer ${accessToken}`,
    },
  }).then((res) => res.json());
  return userResponse.data[0];
}

let token = {
  access_token: null,
  expires_in: null,
  token_type: null,
};

async function registerSuspiciousUserMessageEvent(broadcasterId, moderatorId) {
  let data = {
    type: "channel.suspicious_user.message",
    version: "1",
    condition: {
      broadcaster_user_id: broadcasterId,
      moderator_user_id: moderatorId,
    },
    transport: {
      method: "webhook",
      callback: process.env.URL ?? "https://localhost",
      secret: process.env.EVENTSUB_SECRET,
    },
  };
  console.log(`registerSuspiciousUserMessageEvent:\n${JSON.stringify(data)}`);
  return await fetch("https://api.twitch.tv/helix/eventsub/subscriptions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token.access_token}`,
      "Client-ID": process.env.TWITCH_CLIENT_ID,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  }).then(async (res) => {
    // 202 Accepted = Successfully accepted the subscription request
    // 400 Bad Request
    // 401 Unauthorized
    // 403 Forbidden = 	The access token is missing the required scopes.
    // 409 Conflict - A subscription already exists for the specified event type and condition combination
    // 429 Too Many Requests - The request exceeds the number of subscriptions that you may create with the same combination of type and condition values.
    console.log(`${res.status}:\n${JSON.stringify(await res.json(), null, 2)}`);
    if (res.status >= 200 && res.status < 300) {
      return true;
    } else {
      return false;
    }
  });
}

async function getToken() {
  let clientCredentials = await fetch(
    `https://id.twitch.tv/oauth2/token?client_id=${process.env.TWITCH_CLIENT_ID}&client_secret=${process.env.TWITCH_CLIENT_SECRET}&grant_type=client_credentials`,
    {
      method: "POST",
    },
  );
  if (clientCredentials.status >= 200 && clientCredentials.status < 300) {
    let clientCredentialsJson = await clientCredentials.json();
    token = {
      access_token: clientCredentialsJson.access_token,
      expires_in: clientCredentialsJson.expires_in,
      token_type: clientCredentialsJson.token_type,
    };
    return token;
  }
}

const readlineInterface = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});
readlineInterface.question(
  "Enter the User whose Channel you want to monitor:\n",
  async (user) => {
    await getToken();
    await registerSuspiciousUserMessageEvent(
      (
        await getUser(
          process.env.TWITCH_CLIENT_ID,
          token.access_token,
          user.toLowerCase(),
        )
      ).id,
      process.env.MODERATOR_ID,
    );
    readlineInterface.close();
  },
);
