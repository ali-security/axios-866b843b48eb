import assert from 'assert';
import vm from 'vm';
import utils from '../../../lib/utils.js';

describe('utils::prototype-safe property helpers', function () {
  afterEach(function () {
    delete Object.prototype.polluted;
    delete Object.prototype[Symbol.iterator];
  });

  it('should ignore members inherited only from Object.prototype', function () {
    Object.prototype.polluted = 'yes';

    const source = { own: 'value' };

    assert.strictEqual(utils.hasOwnInPrototypeChain(source, 'polluted'), false);
    assert.strictEqual(utils.getSafeProp(source, 'polluted'), undefined);
    assert.strictEqual(utils.getSafeProp(source, 'own'), 'value');

    const flattened = utils.toSafeFlatObject(source);

    assert.notStrictEqual(flattened, source);
    assert.strictEqual(Object.getPrototypeOf(flattened), null);
    assert.strictEqual(flattened.own, 'value');
    assert.strictEqual('polluted' in flattened, false);
  });

  it('should ignore members inherited from a foreign realm Object.prototype', function () {
    const source = vm.runInNewContext(
      "Object.prototype.polluted = 'yes'; ({ own: 'value' });"
    );

    assert.strictEqual(utils.getSafeProp(source, 'polluted'), undefined);
    assert.strictEqual(utils.getSafeProp(source, 'own'), 'value');

    const flattened = utils.toSafeFlatObject(source);

    assert.strictEqual(flattened.own, 'value');
    assert.strictEqual('polluted' in flattened, false);
  });

  it('should keep class and template members below the shared prototype', function () {
    class Template {
      get accessor() {
        return 'accessor';
      }

      method() {
        return 'method';
      }
    }

    const instance = new Template();
    instance.own = 'value';

    assert.strictEqual(utils.getSafeProp(instance, 'accessor'), 'accessor');
    assert.strictEqual(utils.getSafeProp(instance, 'own'), 'value');

    const flattened = utils.toSafeFlatObject(instance);

    assert.strictEqual(Object.getPrototypeOf(flattened), null);
    assert.strictEqual(flattened.own, 'value');
    assert.strictEqual(flattened.accessor, 'accessor');
    assert.strictEqual(flattened.method(), 'method');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'constructor'), false);
  });

  it('should return non-object values unchanged', function () {
    assert.strictEqual(utils.toSafeFlatObject(undefined), undefined);
    assert.strictEqual(utils.toSafeFlatObject(null), null);
    assert.strictEqual(utils.toSafeFlatObject('str'), 'str');
    assert.strictEqual(utils.getSafeProp(null, 'x'), undefined);
  });

  it('should treat plain objects as plain when Object.prototype[Symbol.iterator] is polluted', function () {
    Object.defineProperty(Object.prototype, Symbol.iterator, {
      configurable: true,
      writable: true,
      value: function* () {
        yield ['x', '1'];
      }
    });

    try {
      assert.strictEqual(utils.isPlainObject({ a: 1 }), true);
    } finally {
      delete Object.prototype[Symbol.iterator];
    }
  });

  it('should keep treating objects with an own or class iterator as non-plain', function () {
    const own = { a: 1 };
    own[Symbol.iterator] = function* () {};

    assert.strictEqual(utils.isPlainObject(own), false);
    assert.strictEqual(utils.isPlainObject(new Map()), false);
    assert.strictEqual(utils.isPlainObject(Object.create({})), false);
  });

  it('should ignore an iterator inherited from a terminal null-prototype boundary', function () {
    // A terminal application template is indistinguishable from a mutated
    // foreign Object.prototype, so its inherited members fail closed.
    const proto = Object.create(null);
    proto[Symbol.iterator] = function* () {
      yield ['x', '1'];
    };

    assert.strictEqual(utils.isPlainObject(Object.create(proto)), true);
  });

  it('should stop safe prototype flattening on cyclic Proxy prototypes', function () {
    let calls = 0;
    let proxy;
    proxy = new Proxy({}, {
      getPrototypeOf() {
        calls += 1;
        if (calls > 1) {
          throw new Error('cycled');
        }
        return proxy;
      }
    });

    assert.deepStrictEqual(Object.keys(utils.toSafeFlatObject(proxy)), []);
    assert.strictEqual(calls, 1);
  });

  it('should preserve null-prototype sources but exclude terminal templates', function () {
    const root = Object.create(null);
    root.own = 'preserved';

    assert.strictEqual(utils.getSafeProp(root, 'own'), 'preserved');
    assert.strictEqual(utils.toSafeFlatObject(root), root);

    const template = Object.create(null);
    template.inherited = 'excluded';

    const source = Object.create(template);
    source.own = 'preserved';

    assert.strictEqual(utils.getSafeProp(source, 'own'), 'preserved');
    assert.strictEqual(utils.getSafeProp(source, 'inherited'), undefined);

    const flattened = utils.toSafeFlatObject(source);

    assert.strictEqual(flattened.own, 'preserved');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'inherited'), false);
  });

  it('should materialize immutable null-prototype sources', function () {
    const source = Object.freeze(Object.assign(Object.create(null), { own: 'preserved' }));
    const flattened = utils.toSafeFlatObject(source);

    assert.notStrictEqual(flattened, source);
    assert.strictEqual(Object.getPrototypeOf(flattened), null);
    assert.strictEqual(flattened.own, 'preserved');
    assert.strictEqual(Object.isFrozen(flattened), false);
  });

  it('should materialize and filter unsafe keys from null-prototype sources', function () {
    const source = Object.create(null);
    source.safe = 'preserved';
    Object.defineProperty(source, '__proto__', {
      value: 'excluded',
      enumerable: true,
      configurable: true,
      writable: true
    });
    source.constructor = 'excluded';
    source.prototype = 'excluded';

    const flattened = utils.toSafeFlatObject(source);

    assert.notStrictEqual(flattened, source);
    assert.strictEqual(flattened.safe, 'preserved');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, '__proto__'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'constructor'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'prototype'), false);
  });

  it('should exclude symbols inherited from terminal null-prototype templates', function () {
    const behavior = Symbol('behavior');
    const template = Object.create(null);
    template[behavior] = () => 'excluded';

    const source = Object.create(template);
    const flattened = utils.toSafeFlatObject(source);

    assert.strictEqual(utils.getSafeProp(source, behavior), undefined);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, behavior), false);
  });
});
