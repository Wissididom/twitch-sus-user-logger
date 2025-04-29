import { getUser as getUserImpl } from "./utils.js";

async function getUser(
  id,
  clientId = process.env.TWITCH_CLIENT_ID,
  accessToken,
) {
  return getUserImpl(id, clientId, accessToken);
}

function redirect(res, clientId, redirectUri, scopes) {
  res.redirect(
    `https://id.twitch.tv/oauth2/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${encodeURIComponent(scopes.join(" "))}`,
  );
}

export function auth(res, clientId, redirectUri, manage) {
  if (manage) {
    redirect(res, clientId, redirectUri, ["moderator:manage:unban_requests"]);
  } else {
    redirect(res, clientId, redirectUri, ["moderator:read:unban_requests"]);
  }
}

function getAccessLevel(scopes) {
  if (scopes.includes("moderator:manage:unban_requests")) {
    return "Manage";
  } else {
    return "Read";
  }
}

export async function authCallback(req, res) {
  res.setHeader("content-type", "text/plain");
  if (req.query.code) {
    const authCode = req.query.code;
    const fetchResponse = await fetch("https://id.twitch.tv/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: process.env.TWITCH_CLIENT_ID,
        client_secret: process.env.TWITCH_CLIENT_SECRET,
        code: authCode,
        grant_type: "authorization_code",
        redirect_uri: process.env.TWITCH_REDIRECT_URI,
      }),
    });
    if (fetchResponse.ok) {
      const json = await fetchResponse.json();
      const accessToken = json.access_token;
      const user = await getUser(
        null,
        process.env.TWITCH_CLIENT_ID,
        accessToken,
      );
      const accessLevel = getAccessLevel(json.scope);
      if (user.display_name.toLowerCase() == user.login) {
        res.send(`Got ${accessLevel} Tokens for ${user.display_name}`);
      } else {
        res.send(
          `Got ${accessLevel} Tokens for ${user.display_name} (${user.login})`,
        );
      }
    } else {
      res.send(await fetchResponse.text());
    }
  } else if (req.query.error) {
    if (req.query.error_description) {
      res.send(
        `The following error occured:\n${req.query.error}\n${req.query.error_description}`,
      );
    } else {
      res.send(`The following error occured:\n${req.query.error}`);
    }
  } else {
    res.send(
      "This endpoint is intended to be redirected from Twitch's auth flow. It is not meant to be called directly",
    );
  }
}
