import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { generateJwtCircuitParams, generateJwtInputs } from "../../src/jwt.ts";
import { sha256 } from "@noble/hashes/sha2";

describe("JWT Verifier", () => {
  let circuit!: WitnessTester<any, any>;

  describe("Age JWT Claim", () => {
    before(async () => {
      const RECOMPILE = true;
      circuit = await circomkit.WitnessTester(`JWT`, {
        file: "jwt",
        template: "JWT",
          params: [2048, 2000, 4, 50, 128],
        recompile: RECOMPILE,
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify Taiwan Vc JWT", async () => {
      const token_with_claims =
        "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkva2V5cyIsImtpZCI6ImtleS0xIiwidHlwIjoidmMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkaWQ6a2V5OnpZcU52VkNrWVhhTXNGVVhEemJvRk1DMXRSV0ZjOHBUTGRONTgzb3FhcG9LNk1veno5dEVWVWpYU2lDN3Y2eXlOR0I4TW5DZUh1SE5hWlpzczFYS1E5dktzY2EyN0VIM0NQTXFSSnN5b2pqdXRyNEtrMzJaWVE0TDRjdHpZaDVHMWhrR1I3VFlhQ0Q3ekczWU1WS0V2dWQxejhZVnR5N2lxZzhBVTZxQ3hvS25ibkVVNnJEQSIsIm5iZiI6MTczOTgxNjY3MiwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JzWTlEUnFTQ2d6elJ1RmJwcTlxd0pUTGtCbm1tQlhoZFNkcTZCREpSTXg2dENHMWp0a2R3Z0tYTmZOMXFXRVJEdnhhYzVyWTZoY25GUDdIdjYzaU01eTNWeHRNTjRUc3h5WnZibnJhcFcyUnBGb3ZFMURKNG03ZURWTFN1cUd0YzFpIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlBrcV82ZDJpeUIwZGVvalYyLXlta0ZWeUpNeElfTDlHZVF4aDBORExoNDQ9IiwieSI6IjBOZnFMdmUtSXEwSFZZUE11eEctWHpRNUlmNktaOFhvQ0hkNmZOaDhsZFU9In19LCJleHAiOjY3OTc3NzcxODcyLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiOTM1ODE5MjVfZGQiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMtdWF0LndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzkzNTgxOTI1X2RkL3IwIzYiLCJzdGF0dXNMaXN0SW5kZXgiOiI2Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvOTM1ODE5MjVfZGQvcjAiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9mcm9udGVuZC11YXQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzkzNTgxOTI1L2RkL1YxL2Q0ZDFhMGY5LTNmMDktNGMyZS1iODk5LTA4YzM0NDkwYzhlYSIsInR5cGUiOiJKc29uU2NoZW1hIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJKY2lHYzViS2lkT0dteGp1dkM4TGRVeWthVlhCWEJQaEJYMWtYcERlLUxvIiwicFZPdzJOajU3RzJOa2VWSEJDV3doRUJqdWZTSmhwOWxwM201VzltQWg5QSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9fSwibm9uY2UiOiJCSElDVTI2TiIsImp0aSI6Imh0dHBzOi8vaXNzdWVyLXZjLXVhdC53YWxsZXQuZ292LnR3L2FwaS9jcmVkZW50aWFsLzRmYzNiYTY1LTY1ZGQtNDEyNC05ZTczLWNhOWY0OWNkNzc2NyJ9.h0wBjwjBDb48wZ_XVWnnrRrWh2Sgd4Lq7sc72N54svJFklnFuHebxvn-Ui6jftnQbPnLTKEyJbE75DatCkfkdQ~WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ~WyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd";
      // let hashedClaims = ["JciGc5bKidOGmxjuvC8LdUykaVXBXBPhBX1kXpDe-Lo", "pVOw2Nj57G2NkeVHBCWwhEBjufSJhp9lp3m5W9mAh9A"];

      const [token, ...claims] = token_with_claims.split("~");

      let hashedClaims = claims.map((claim) => {
        const claimBuffer = Uint8Array.from(Buffer.from(claim, "utf8"));
        return Buffer.from(sha256(claimBuffer)).toString("base64url");
      });

      // JSON Web Key Set(JWKS) taken from "jku":"https://issuer-vc-uat.wallet.gov.tw/api/keys",
      const jwk = {
        kty: "EC",
        crv: "P-256",
        kid: "key-1",
        x: "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
        y: "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I",
      };

      const params = generateJwtCircuitParams([2048, 2000, 4, 50, 128]);

  const inputs = generateJwtInputs(params, token, jwk, hashedClaims, claims);
      const witness = await circuit.calculateWitness(inputs);

      await circuit.expectConstraintPass(witness);
    });
  });

  describe("Production-Style Fixture Verification", () => {
    before(async () => {
      const RECOMPILE = true;
      circuit = await circomkit.WitnessTester(`JWT`, {
        file: "jwt",
        template: "JWT",
        params: [1024 * 3, 2200, 8, 50, 128],
        recompile: RECOMPILE,
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify Taiwan VC JWT", async () => {
      const token_with_claims =
        "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9rZXlzIiwia2lkIjoia2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BvZHJaU3FNYkN5OU5kdTRVZ1VHeTNSTmtoSDQ3OWVMUHBiZkFoVlNOdTdCNG9KdlV3THp5eGlQNEp0NWs5Y3FxbUNoYW54QWF6VEd4Sk12R3hZREFwTmtYZURXNU1QWmdaUmtqUmdEMXlhaWc1S0NFZ0FhVmJnOHpydllqTVRpMUJ6cWREcFBwa2VTRm1Kd2llajlZTlkiLCJuYmYiOjE3NDg0NDk5OTksImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticlRRV1BUSk10MkZ1MTZIODR5bXdiYkc5TEdOaW5XN1luajUzWkNBVzE2Z3JBaEJpd3Y1M0FuYnY3ODdodDZueGFLTUdHQWdZOVdqdEZ4WVozaGpHZE1kMVNodVFvU3ZOZVh4Y2o1SmNiazJ1WXRmR2J3aW9GU2laUVhmekg3Y3RoaSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI0OXJrcUxQb2JSRWdjcDZSSHpKNTJsNWdjQXpmSG9yZWVXbWtMTTdhQzJ3IiwieSI6IlQ2SFB5OWZnN1FOV2RvTWt2UFVOajBLeFgtUVIzeS14NUdKbmtnc2hzZnMifX0sImV4cCI6MjA2Mzk4Mjc5OSwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4Il0sImNyZWRlbnRpYWxTdGF0dXMiOnsidHlwZSI6IlN0YXR1c0xpc3QyMDIxRW50cnkiLCJpZCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIzIwIiwic3RhdHVzTGlzdEluZGV4IjoiMjAiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL2RlbW9kcml2aW5nbGljZW5zZTIwMjUwNDI1MTQxOC9WMS9iNjUzYWQ0Yi0zYjNhLTQ2ZjktYmVjMi1kNjg3Y2U5YzMyMjIiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiQWVsYmY0WVl0YzhCRGZhck9NMlA5NWRocHBMWU9rb2hmNkR0Z1VqZmhZVSIsIkdPdjR1Y0pjS0drMEVfb0UwZ2VJbXhTRjg5bm5IcHotUWJOclZWOXcyUm8iLCJMSkxCaGVHa3VFU1N1RXlHQkJ2U01XOXRiMHFab1B1NUtrZjVnMUMzQmZrIiwiWS0tUWIyOG5kcUVHX2YtSEdLczZvMnJJUVpVUGd2RmticWJxTGhzY0hjZyIsImNWMGROYm0wNTlfSEo2c000bkM2eUVSNE1neTdneVV2SVlGUG8tc3U0RkUiLCJyZTU0VTFZZHV5alhXLTQwVlIxc2U5cVhZM081U19UdDFpSzNsUXlUa0Y4Il0sIl9zZF9hbGciOiJzaGEtMjU2In19LCJub25jZSI6Ikk5UTBPQzNOIiwianRpIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvY3JlZGVudGlhbC9iNzZiOTg4OC01MTFmLTQ5YTAtYjI2Yi0yYjU4YzhjNTczMDIifQ.eGndfGnmzkxRoVMLJaLVZiqxmpiccnMcdq1ytef72fGSRyqSY_tz6EF7nlyNH9FsSOBCZ6RKgfPk6HGNbk3SKg~WyJPVWpCZ1E4RFVnenRRR3dxaWVhZE13IiwibmFtZSIsIumZs-etseeOsiJd~WyJRdWRNTnlPelV2TEJQYXVrT1pfcVlnIiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd~WyI4STBWclR0QnpNdlFFSmxmV2hqS2FBIiwicm9jX2JpcnRoZGF5IiwiMTA0MDYwNSJd~WyJhVVBlVWhVOEtRLTE4eG9DTGVDN1FRIiwidHlwZSIsIuaZrumAmuWwj-Wei-i7iiJd~WyJvQndUa0JUdmQzS2pBSXB3U21XUjNBIiwiY29udHJvbG51bWJlciIsIjQwMTA0MDIwOTE0NDUiXQ~WyJlcGtGMjdwejFVY01naHRYRV96Vi1BIiwiZ0RhdGUiLCIxMDIwNzAxIl0~";

      let [token, ...claims] = token_with_claims.split("~");
      claims = claims.filter((claim) => claim.length > 0);

      let hashedClaims = claims.map((claim) => {
        const claimBuffer = Uint8Array.from(Buffer.from(claim, "utf8"));
        return Buffer.from(sha256(claimBuffer)).toString("base64url");
      });

      const jwk = {
        kty: "EC",
        crv: "P-256",
        kid: "key-1",
        x: "dnQ2W9ZTsILYac3XdcvxrYNgIgjSkGJUMecMXVJk7XM",
        y: "0WhT_VgvnhNNj9aabTn4E4enR-iqbCrQtY9UWqD4XJY",
      };

      const params = generateJwtCircuitParams([1024 * 3, 2200, 8, 50, 128]);
      const inputs = generateJwtInputs(params, token, jwk, hashedClaims, claims);

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
    });
  });
});
