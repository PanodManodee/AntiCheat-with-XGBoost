# core/names/ename.py
"""UE5 hardcoded name indices (EName)."""
from enum import IntEnum


class EName(IntEnum):
    """
    UE5 hardcoded FName indices.
    Values must match engine's NAME_* constants.
    """
    # fmt: off
    None_ = 0

    # Property types
    ByteProperty = 1
    IntProperty = 2
    BoolProperty = 3
    FloatProperty = 4
    ObjectProperty = 5
    NameProperty = 6
    DelegateProperty = 7
    DoubleProperty = 8
    ArrayProperty = 9
    StructProperty = 10
    VectorProperty = 11
    RotatorProperty = 12
    StrProperty = 13
    TextProperty = 14
    InterfaceProperty = 15
    MulticastDelegateProperty = 16
    LazyObjectProperty = 18
    SoftObjectProperty = 19
    Int64Property = 20
    Int32Property = 21
    Int16Property = 22
    Int8Property = 23
    UInt64Property = 24
    UInt32Property = 25
    UInt16Property = 26
    MapProperty = 28
    SetProperty = 29
    EnumProperty = 34
    OptionalProperty = 35
    Utf8StrProperty = 36
    AnsiStrProperty = 37

    # Core modules
    Core = 30
    Engine = 31
    Editor = 32
    CoreUObject = 33

    # Math types
    Cylinder = 50
    BoxSphereBounds = 51
    Sphere = 52
    Box = 53
    Vector2D = 54
    IntRect = 55
    IntPoint = 56
    Vector4 = 57
    Name = 58
    Vector = 59
    Rotator = 60
    SHVector = 61
    Color = 62
    Plane = 63
    Matrix = 64
    LinearColor = 65
    AdvanceFrame = 66
    Pointer = 67
    Double = 68
    Quat = 69
    Self = 70
    Transform = 71
    Vector3f = 72
    Vector3d = 73
    Plane4f = 74
    Plane4d = 75
    Matrix44f = 76
    Matrix44d = 77
    Quat4f = 78
    Quat4d = 79
    Transform3f = 80
    Transform3d = 81
    Box3f = 82
    Box3d = 83
    BoxSphereBounds3f = 84
    BoxSphereBounds3d = 85
    Vector4f = 86
    Vector4d = 87
    Rotator3f = 88
    Rotator3d = 89
    Vector2f = 90
    Vector2d = 91
    Box2D = 92
    Box2f = 93
    Box2d = 94
    IntVector = 95
    IntVector4 = 96
    UintVector = 97
    UintVector4 = 98

    # Object types
    Object = 100
    Camera = 101
    Actor = 102
    ObjectRedirector = 103
    ObjectArchetype = 104
    Class = 105
    ScriptStruct = 106
    Function = 107
    Pawn = 108

    # Extended vector types
    Int32Vector = 150
    Int64Vector = 151
    Uint32Vector = 152
    Uint64Vector = 153
    Int32Vector4 = 154
    Int64Vector4 = 155
    Uint32Vector4 = 156
    Uint64Vector4 = 157
    IntVector2 = 158
    Int32Vector2 = 159
    Int64Vector2 = 160
    UintVector2 = 161
    Uint32Vector2 = 162
    Uint64Vector2 = 163
    UintPoint = 164
    Int32Point = 165
    Int64Point = 166
    Uint32Point = 167
    Uint64Point = 168
    Ray = 169
    Ray3f = 170
    Ray3d = 171
    Sphere3f = 172
    Sphere3d = 173

    # Keywords
    State = 200
    TRUE = 201
    FALSE = 202
    Enum = 203
    Default = 204
    Skip = 205
    Input = 206
    Package = 207
    Groups = 208
    Interface = 209
    Components = 210
    Global = 211
    Super = 212
    Outer = 213
    Map = 214
    Role = 215
    RemoteRole = 216
    PersistentLevel = 217
    TheWorld = 218
    PackageMetaData = 219
    InitialState = 220
    Game = 221
    SelectionColor = 222
    UI = 223
    ExecuteUbergraph = 224
    DeviceID = 225
    RootStat = 226
    MoveActor = 227
    All = 230
    MeshEmitterVertexColor = 231
    TextureOffsetParameter = 232
    TextureScaleParameter = 233
    ImpactVel = 234
    SlideVel = 235
    TextureOffset1Parameter = 236
    MeshEmitterDynamicParameter = 237
    ExpressionInput = 238
    Untitled = 239
    Timer = 240
    Team = 241
    Low = 242
    High = 243
    NetworkGUID = 244
    GameThread = 245
    RenderThread = 246
    OtherChildren = 247
    Location = 248
    Rotation = 249
    BSP = 250
    EditorSettings = 251
    AudioThread = 252
    ID = 253
    UserDefinedEnum = 254

    # Channel types
    Control = 255
    Voice = 256

    # Compression
    Zlib = 257
    Gzip = 258
    LZ4 = 259
    Mobile = 260
    Oodle = 261

    # Anti-cheat
    BattlEye = 262
    TrashedPackage = 263

    # Network
    DGram = 280
    Stream = 281
    GameNetDriver = 282
    PendingNetDriver = 283
    BeaconNetDriver = 284
    FlushNetDormancy = 285
    DemoNetDriver = 286
    GameSession = 287
    PartySession = 288
    GamePort = 289
    BeaconPort = 290
    MeshPort = 291
    MeshNetDriver = 292
    LiveStreamVoice = 293
    LiveStreamAnimation = 294
    DataStream = 295

    # Rendering
    Linear = 300
    Point = 301
    Aniso = 302
    LightMapResolution = 303
    UnGrouped = 311
    VoiceChat = 312

    # Game states
    Playing = 320
    Spectating = 322
    Inactive = 325

    # Logging
    PerfWarning = 350
    Info = 351
    Init = 352
    Exit = 353
    Cmd = 354
    Warning = 355
    Error = 356

    # Misc
    FontCharacter = 400
    InitChild2StartBone = 401
    SoundCueLocalized = 402
    SoundCue = 403
    RawDistributionFloat = 404
    RawDistributionVector = 405
    InterpCurveFloat = 406
    InterpCurveVector2D = 407
    InterpCurveVector = 408
    InterpCurveTwoVectors = 409
    InterpCurveQuat = 410
    FrameRate = 411
    AI = 450
    NavMesh = 451
    PerformanceCapture = 500
    EditorLayout = 600
    EditorKeyBindings = 601
    GameUserSettings = 602
    Filename = 700
    Lerp = 701
    Root = 702
    BlueprintDouble = 1000
    MaxHardcodedNameIndex = 1001
    # fmt: on