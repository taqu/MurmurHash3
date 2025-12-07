# MurmurHash3 for C#

A pure C# implementation of **MurmurHash3** supporting **32-bit**, **64-bit**, and **128-bit** hashing, including **incremental hashing**.

# Usage

## Simple hash

```csharp
using System.Text;
using MurmurHash;

byte[] data = Encoding.UTF8.GetBytes("Hello, world!");
byte[] hash32 = MurmurHash3.ComputeHash32(data); // 32-bit Hash
byte[] hash64 = MurmurHash3.ComputeHash64(data); // 64-bit Hash
byte[] hash128 = MurmurHash3.ComputeHash128(data); // 128-bit Hash
````

## Hash with offset and length

```csharp
byte[] hash = MurmurHash3.ComputeHash32(buffer, offset, length);
```

## Hashing stream

```csharp
using (MemoryStream stream = new MemoryStream(data))
{
    byte[] hash = MurmurHash3.ComputeHash128(stream);
}
```

## Incremental hashing

```csharp
byte[] chunk1;
byte[] chunk2;

MurmurHash3.State128 state = new MurmurHash3.State128();
MurmurHash3.Update128(state, chunk1);
MurmurHash3.Update128(state, chunk2);

byte[] hash = MurmurHash3.Finalize128(state);
```

## License

This project is released under the MIT License or the Public Domains.

