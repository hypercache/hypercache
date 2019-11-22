const { hash, uuid: _uuid, encryptSym, pair } = require("./utils/crypto");

function ledger() {
  // instance variables
  let map = new Map();
  let user = null;

  // work?
  const doWork = () => {
    let val = hash();
    while (!val.includes("0000")) {
      val = hash();
    }
    return true;
  };

  const uuid = () => {
    let newId = _uuid();
    while (map.has(newId)) {
      newId = _uuid();
    }
    return newId;
  };

  return {
    createdAt: new Date().getTime(),
    get: key => {
      // check to see if this is a user,
      // and if so only return non-encrypted data if they're not logged in
      return map.get(key);
    },
    set: value => {
      const id = uuid();
      // Make them work for it, to increase write-time complexity
      doWork();

      // if signed in or subbed to an id, push the update to the listener /update the local user
      // if signed in, add in hash to verify that a specific user set a specific value
      if (typeof value === "string") {
        map.set(id, {
          _: id,
          val: value
        });
        return id;
      } else if (typeof value === "object") {
        map.set(id, {
          _: id,
          ...value
        });
        return id;
      } else {
        throw Error("Can only save strings and objects");
      }
    },
    hash,
    doWork,
    register: async (alias, password) => {
      try {
        if (map.has(alias)) {
          throw Error("Alias must be unique");
        }

        const newId = uuid();
        const hashedPassword = hash(password);
        const newPair = await pair(hashedPassword);

        const newUser = {
          id: newId,
          alias,
          profile: encryptSym(JSON.stringify(newPair), hashedPassword),
          createdAt: new Date().getTime(),
          updatedAt: new Date().getTime()
        };

        map.set(alias, newUser);
        map.set(newId, newUser);

        return true;
      } catch {
        throw Error("Error regsitering user");
      }
    },
    login: (alias, password) => {
      try {
        const prospectiveUserEnc = map.get(alias);
        const hashedPassword = hash(password);

        console.log(prospectiveUserEnc);
        console.log(decryptSym(user.profile, hashedPassword));

        // const decryptedUser = {
        //   ...prospectiveUserEnc,
        //   profile: JSON.parse(decryptSym(user.profile, hashedPassword))
        // };

        // // set this instance to logged in
        // user = decryptedUser;

        return user;
      } catch {
        throw Error("Invalid Password");
      }
    },

    user: user
  };
}

(async () => {
  let cache = ledger();

  // test set and get
  const id = cache.set("Someone's name");
  console.log("returned id", id);
  console.log(cache.get(id));

  // test register
  let res1 = await cache.register("john", "password123");
  console.log("did register succeed:", res1);
  console.log("------------------------------");
  console.log("==============================");
  console.log("------------------------------");

  // test login
  let res2 = cache.login("john", "password123");
  console.log("user", res2);
})();
