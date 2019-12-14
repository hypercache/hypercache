const {
  hash,
  uuid: _uuid,
  encryptSym,
  decryptSym,
  pair,
  sign,
  verify
} = require("./utils/crypto");

function ledger() {
  // instance variables
  let _map = new Map();
  let _user = null;

  // work?
  const doWork = () => {
    let val = hash();
    while (!val.includes("0000")) {
      val = hash();
    }
    return true;
  };

  // guarantee a unique id
  const uuid = () => {
    let newId = _uuid();
    while (_map.has(newId)) {
      newId = _uuid();
    }
    return newId;
  };

  const _set = (id, value) => {
    if (!id) {
      id = uuid();
    }
    let newObj;

    // if signed in or subbed to an id, push the update to the listener /update the local user
    // if signed in, add in hash to verify that a specific user set a specific value
    if (typeof value === "string") {
      newObj = {
        _: id,
        val: value,
        updatedAt: new Date().getTime(),
        createdAt: new Date().getTime()
      };
    } else if (isObj(value)) {
      newObj = {
        _: id,
        ...value,
        updatedAt: new Date().getTime(),
        createdAt: new Date().getTime()
      };
    } else {
      throw Error("Can only save strings and objects");
    }

    // if the user is signed in, sign the change
    if (_user) {
      newObj = {
        ...newObj,
        "#": sign(
          _user.profile.priv,
          _user.profile.pass,
          JSON.stringify(newObj)
        )
      };
    }
    _map.set(id, newObj);
    return id;
  };

  // utility mthod to check if something is an object is object literal
  const isObj = _obj => {
    var _test = _obj;
    return typeof _obj !== "object" || _obj === null
      ? false
      : (function() {
          while (!false) {
            if (
              Object.getPrototypeOf((_test = Object.getPrototypeOf(_test))) ===
              null
            ) {
              break;
            }
          }
          return Object.getPrototypeOf(_obj) === _test;
        })();
  };

  // verify helper method
  const _verify = (id, pub) => {
    let signedItem = _map.get(id);
    let sig = signedItem["#"];
    delete signedItem["#"];
    return verify(pub, JSON.stringify(signedItem), sig);
  };

  // return our hyperCache interface
  return {
    createdAt: new Date().getTime(),
    get: key => {
      // check to see if this is a user,
      // and if so only return non-encrypted data if they're not logged in

      // check to see if the value is a "pointer" to another value like alias -> alias.id
      return _map.get(key);
    },
    set: value => {
      return _set(null, value);
    },
    update: (key, value) => {
      try {
        // if this value has been set already, verify the owner
        if (!_map.has(key)) {
          throw Error("Value doesn't exist");
        }

        if (!_user) {
          throw Error("Cannot update signed data, must be logged in.");
        }

        const belongsToThisUser = _verify(key, _user.profile.pub);

        if (belongsToThisUser) {
          // the user already has the id, so return the whole new node
          return _map.get(_set(key, value));
        }

        throw Error("Cannot update data that doesn't belong to user");
      } catch (e) {
        throw Error(e);
      }
    },
    hash,
    doWork,
    register: async (alias, password) => {
      try {
        if (_map.has(alias)) {
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

        // set both alias and user id as this user (replace alias, value with reference to id)
        _map.set(alias, newUser);
        _map.set(newId, newUser);

        return true;
      } catch {
        throw Error("Error registering user");
      }
    },
    logout: () => {
      _user = null;
      return true;
    },
    login: (alias, password) => {
      try {
        const prospectiveUserEnc = _map.get(alias);
        const hashedPassword = hash(password);

        // decrypt the user's personal keys for their access only
        const decryptedUser = {
          ...prospectiveUserEnc,
          profile: JSON.parse(
            decryptSym(prospectiveUserEnc.profile, hashedPassword)
          )
        };

        // set this instance to logged in
        _user = decryptedUser;

        return _user;
      } catch (e) {
        throw Error(new Error(e));
      }
    },
    user: () => _user
  };
}

(async () => {
  let cache = ledger();

  // test set and get
  // const id = cache.set("Someone's name");
  // console.log("returned id", id);
  // console.log(cache.get(id));

  // test no logged in user
  // console.log("user", cache.user());

  // test register
  // console.log("----------register------------");
  let res1 = await cache.register("john", "password123");
  // console.log("register result", res1);

  // test login
  // console.log("----------register------------");

  let user = cache.login("john", "password123");
  // console.log("login result", user);

  let circleId = cache.set({ circle: "Mars", preamble: "Wow this is cool" });
  console.log(circleId);

  // // verify signature
  // let signedItem = cache.get(circleId);
  // let sig = signedItem["#"];
  // delete signedItem["#"];
  // console.log(
  //   "verified",
  //   verify(cache.user().profile.pub, JSON.stringify(signedItem), sig)
  // );

  let newNode = cache.update(circleId, {
    circle: "Mars",
    preamble: "Berbebeb"
  });
  console.log(newNode);
  cache.logout();
  try {
    //////////// test changing with no user
    newNode = cache.update(circleId, {
      circle: "NotMars",
      preamble: "bad haxed"
    });
    console.log(newNode);

    ///////////// test changing with wrong user
    await cache.register("jimbo", "password123");
    let user2 = cache.login("jimbo", "password123");
    newNode = cache.update(circleId, {
      circle: "defnotmars",
      preamble: "oisudfviu"
    });
    console.log(newNode);
    /////////

    console.log(cache.get(circleId));
  } catch (e) {
    console.log(cache.get(circleId));

    throw Error(new Error(e));
  }
})();
