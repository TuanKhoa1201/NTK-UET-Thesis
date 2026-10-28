import {useState} from 'react';

const suppliedImage = 'https://media-manager-c.questera.ai/greta-media/2c0237c981eed733b46aeee88d005433f78d1860f932c19fab4ecf29601fa9beaf47dce5eef525a8f30f7f0ceeea8806/images/aW1hZ2UvcG5n/8fcd48109b19706dee1b791d582dad70.png';

export default function UETLogo({variant = 'sidebar'}) {
  const [failed, setFailed] = useState(false);

  return (
    <span className={`uet-image-tile uet-image-tile--${variant}`}>
      {failed ? (
        <span className="uet-image-unavailable" role="img" aria-label="Không tải được logo UET">Logo chưa tải được</span>
      ) : (
        <img
          src={suppliedImage}
          alt="Logo Trường Đại học Công nghệ - Đại học Quốc gia Hà Nội"
          onError={() => setFailed(true)}
        />
      )}
    </span>
  );
}