#version 450
layout(location=0) in vec2 vUv;
layout(location=0) out vec4 fragColor;
layout(set=0, binding=0) uniform sampler2D uScene;
layout(set=0, binding=1) uniform sampler2D uBloom;
layout(push_constant) uniform Push { vec2 dir; float intensity; } pc;
void main() {
    vec4 s = texture(uScene, vUv);
    vec3 b = texture(uBloom, vUv).rgb;
    fragColor = vec4(s.rgb + b * pc.intensity, s.a);
}
