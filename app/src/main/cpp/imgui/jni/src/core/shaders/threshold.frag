#version 450
layout(location=0) in vec2 vUv;
layout(location=0) out vec4 fragColor;
layout(set=0, binding=0) uniform sampler2D uScene;
void main() {
    vec3 c = texture(uScene, vUv).rgb;
    float l = dot(c, vec3(0.299, 0.587, 0.114));
    const float t = 0.30;
    float k = clamp((l - t) / max(0.01, 1.0 - t), 0.0, 1.0);
    fragColor = vec4(c * k, 1.0);
}
