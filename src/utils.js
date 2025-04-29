export async function getUser(id, clientId, accessToken) {
  let apiUrl = id
    ? `https://api.twitch.tv/helix/users?id=${id}`
    : `https://api.twitch.tv/helix/users`;
  let userResponse = await fetch(apiUrl, {
    headers: {
      "Client-ID": clientId,
      Authorization: `Bearer ${accessToken}`,
    },
  }).then((res) => res.json());
  return userResponse.data[0];
}
