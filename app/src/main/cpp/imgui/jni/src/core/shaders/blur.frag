#version 450
layout(location=0) in vec2 vUv;
layout(location=0) out vec4 fragColor;
layout(set=0, binding=0) uniform sampler2D uImage;
layout(push_constant) uniform Push { vec2 dir; float intensity; } pc;
void main() {
    const float w0 = 0.2270270270;
    const float w1 = 0.1945945946;
    const float w2 = 0.1216216216;
    const float w3 = 0.0540540541;
    const float w4 = 0.0162162162;
    vec3 c  = texture(uImage, vUv).rgb * w0;
    c += texture(uImage, vUv + pc.dir * 1.0).rgb * w1;
    c += texture(uImage, vUv - pc.dir * 1.0).rgb * w1;
    c += texture(uImage, vUv + pc.dir * 2.0).rgb * w2;
    c += texture(uImage, vUv - pc.dir * 2.0).rgb * w2;
    c += texture(uImage, vUv + pc.dir * 3.0).rgb * w3;
    c += texture(uImage, vUv - pc.dir * 3.0).rgb * w3;
    c += texture(uImage, vUv + pc.dir * 4.0).rgb * w4;
    c += texture(uImage, vUv - pc.dir * 4.0).rgb * w4;
    fragColor = vec4(c, 1.0);
}
