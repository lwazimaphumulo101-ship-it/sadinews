import { request } from "node:https";
import { lookup } from "node:dns";
import { BlockList, isIP } from "node:net";

const blocked = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
]) blocked.addSubnet(address, prefix, "ipv4");

function invalid(message, status = 400) {
  return Object.assign(new Error(message), { status });
}

function publicAddress(address) {
  return isIP(address) === 4 && !blocked.check(address, "ipv4");
}

function imageUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw invalid("Enter a valid HTTPS image link."); }
  if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443"))
    throw invalid("Use an HTTPS image link without login details or a custom port.");
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (!hostname.includes(".") || (isIP(hostname) && !publicAddress(hostname)))
    throw invalid("Use a publicly accessible image link.");
  url.hash = "";
  return url;
}

function imageType(data) {
  if (data.length >= 8 && data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) return "image/png";
  if (data.length >= 3 && data[0] === 255 && data[1] === 216 && data[2] === 255) return "image/jpeg";
  if (["GIF87a", "GIF89a"].includes(data.subarray(0, 6).toString("ascii"))) return "image/gif";
  if (data.length >= 12 && data.subarray(0, 4).toString("ascii") === "RIFF" && data.subarray(8, 12).toString("ascii") === "WEBP") return "image/webp";
  return null;
}

function download(url, limit, signal) {
  return new Promise((resolve, reject) => {
    const outgoing = request(url, {
      method: "GET", agent: false, family: 4, autoSelectFamily: false, signal,
      headers: { Accept: "image/png,image/jpeg,image/gif,image/webp", "Accept-Encoding": "identity" },
      lookup(hostname, options, callback) {
        lookup(hostname, { family: 4 }, (error, address, family) => {
          if (error) return callback(invalid("The image host could not be reached.", 422));
          if (!publicAddress(address)) return callback(invalid("Use a publicly accessible image link."));
          callback(null, address, family);
        });
      },
    }, (response) => {
      const status = response.statusCode;
      if ([301, 302, 303, 307, 308].includes(status)) {
        const location = response.headers.location;
        response.destroy();
        if (!location) return reject(invalid("The image link has an invalid redirect.", 422));
        try { resolve({ redirect: imageUrl(new URL(location, url).href) }); }
        catch (error) { reject(error); }
        return;
      }
      const type = (response.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
      if (status !== 200 || !["image/png", "image/jpeg", "image/gif", "image/webp"].includes(type)) {
        response.destroy();
        return reject(invalid("That link must open a PNG, JPG, GIF or WebP image directly, not a web page.", 422));
      }
      if (Number(response.headers["content-length"]) > limit) {
        response.destroy();
        return reject(invalid("The cover photo must be 5 MB or smaller.", 413));
      }
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > limit) {
          response.destroy();
          reject(invalid("The cover photo must be 5 MB or smaller.", 413));
        } else chunks.push(chunk);
      });
      response.on("end", () => {
        const data = Buffer.concat(chunks);
        if (!size || imageType(data) !== type)
          return reject(invalid("That link did not return a valid supported image.", 422));
        resolve({ data, type });
      });
      response.on("error", reject);
      response.on("aborted", () => reject(invalid("The image download was interrupted. Try again.", 422)));
    });
    outgoing.on("error", reject);
    outgoing.end();
  });
}

export async function fetchCoverImage(value, limit) {
  if (typeof value !== "string" || !value.trim() || value.length > 2048)
    throw invalid("Enter an image link of 2,048 characters or fewer.");
  let url = imageUrl(value.trim());
  const signal = AbortSignal.timeout(15000);
  try {
    for (let redirects = 0; redirects <= 3; redirects++) {
      const result = await download(url, limit, signal);
      if (!result.redirect) return result;
      url = result.redirect;
    }
    throw invalid("That image link redirects too many times. Use the final image URL.", 422);
  } catch (error) {
    if (error.status) throw error;
    throw invalid(signal.aborted ? "The image download timed out. Try another link." : "The image could not be downloaded. Use a publicly accessible image link.", 422);
  }
}
